package azure

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	n "github.com/Azure/azure-sdk-for-go/services/network/mgmt/2021-03-01/network"
	"github.com/Azure/go-autorest/autorest/to"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/klog/v2"
)

type FakeSender struct {
	statusCode int
	body       *n.ApplicationGateway
}

func (fs *FakeSender) Do(request *http.Request) (response *http.Response, err error) {
	response = &http.Response{
		StatusCode: fs.statusCode,
	}
	if fs.statusCode != 200 {
		err = errors.New("Error while making a GET for the gateway")
	} else {
		if fs.body != nil {
			b, err := json.Marshal(fs.body)
			if err == nil {
				response.Body = io.NopCloser(bytes.NewReader(b))
			}
		}
	}
	return response, err
}

var _ = Describe("generateRandomIPsInSubnet", func() {
	Context("when given a valid subnet CIDR", func() {
		It("should return IPs within the subnet range for /24 network", func() {
			subnetPrefix := to.StringPtr("10.0.1.0/24")
			ips, err := generateRandomIPsInSubnet(subnetPrefix)

			Expect(err).To(BeNil())
			Expect(len(ips)).To(BeNumerically(">", 0))
			Expect(len(ips)).To(BeNumerically("<=", 50)) // limited to maxIPs

			// Verify all IPs are in the subnet range
			_, subnet, _ := net.ParseCIDR(*subnetPrefix)
			for _, ip := range ips {
				parsedIP := net.ParseIP(ip)
				Expect(subnet.Contains(parsedIP)).To(BeTrue(), "IP %s should be in subnet %s", ip, *subnetPrefix)

				// Should not be network or broadcast address
				Expect(ip).ToNot(Equal("10.0.1.0"))   // network address
				Expect(ip).ToNot(Equal("10.0.1.255")) // broadcast address
			}
		})

		It("should return IPs within the subnet range for /28 network", func() {
			subnetPrefix := to.StringPtr("192.168.0.16/28")
			ips, err := generateRandomIPsInSubnet(subnetPrefix)

			Expect(err).To(BeNil())
			Expect(len(ips)).To(BeNumerically(">", 0))
			Expect(len(ips)).To(BeNumerically("<=", 14)) // /28 has 14 usable IPs

			// Verify all IPs are in the subnet range
			_, subnet, _ := net.ParseCIDR(*subnetPrefix)
			for _, ip := range ips {
				parsedIP := net.ParseIP(ip)
				Expect(subnet.Contains(parsedIP)).To(BeTrue(), "IP %s should be in subnet %s", ip, *subnetPrefix)

				// Should not be network or broadcast address
				Expect(ip).ToNot(Equal("192.168.0.16")) // network address
				Expect(ip).ToNot(Equal("192.168.0.31")) // broadcast address
			}
		})

		It("should return IPs within the subnet range for /30 network", func() {
			subnetPrefix := to.StringPtr("172.16.0.0/30")
			ips, err := generateRandomIPsInSubnet(subnetPrefix)

			Expect(err).To(BeNil())
			Expect(len(ips)).To(Equal(2)) // /30 has only 2 usable IPs

			// Verify all IPs are in the subnet range and are the expected ones
			expectedIPs := []string{"172.16.0.1", "172.16.0.2"}
			for _, ip := range ips {
				Expect(expectedIPs).To(ContainElement(ip))
			}
		})

		It("should handle large subnets by limiting to maxIPs", func() {
			subnetPrefix := to.StringPtr("10.0.0.0/16")
			ips, err := generateRandomIPsInSubnet(subnetPrefix)

			Expect(err).To(BeNil())
			Expect(len(ips)).To(Equal(50)) // should be limited to maxIPs

			// Verify all IPs are in the subnet range
			_, subnet, _ := net.ParseCIDR(*subnetPrefix)
			for _, ip := range ips {
				parsedIP := net.ParseIP(ip)
				Expect(subnet.Contains(parsedIP)).To(BeTrue(), "IP %s should be in subnet %s", ip, *subnetPrefix)
			}
		})

		It("should produce different results on multiple calls (randomization)", func() {
			subnetPrefix := to.StringPtr("10.0.2.0/24")

			// Get two sets of IPs
			ips1, err1 := generateRandomIPsInSubnet(subnetPrefix)
			ips2, err2 := generateRandomIPsInSubnet(subnetPrefix)

			Expect(err1).To(BeNil())
			Expect(err2).To(BeNil())
			Expect(len(ips1)).To(BeNumerically(">", 10)) // ensure we have enough IPs to test randomization
			Expect(len(ips2)).To(BeNumerically(">", 10))

			// Check that the order is different (randomization)
			// Convert to strings for easier comparison
			ips1Str := strings.Join(ips1[:10], ",")
			ips2Str := strings.Join(ips2[:10], ",")

			Expect(ips1Str).ToNot(Equal(ips2Str), "IP lists should be in different order due to randomization")
		})
	})

	Context("when given invalid input", func() {
		It("should return error for invalid CIDR", func() {
			subnetPrefix := to.StringPtr("invalid-cidr")
			ips, err := generateRandomIPsInSubnet(subnetPrefix)

			Expect(err).To(HaveOccurred())
			Expect(ips).To(BeNil())
		})

		It("should return error for nil subnet prefix", func() {
			ips, err := generateRandomIPsInSubnet(nil)

			Expect(err).To(HaveOccurred())
			Expect(ips).To(BeNil())
		})
	})
})

var _ = DescribeTable("Az Application Gateway failures using authorizer", func(statusCodeArg int, errorExpected bool) {
	var azClient = NewAzClient("", "", "", "", "")
	var fakeSender = &FakeSender{
		statusCode: statusCodeArg,
		body:       &n.ApplicationGateway{},
	}
	retryDuration, err := time.ParseDuration("2ms")
	if err != nil {
		klog.Error("Invalid retry duration value")
	}
	azClient.SetDuration(retryDuration)
	azClient.SetSender(fakeSender)
	err = azClient.WaitForGetAccessOnGateway(3)
	if errorExpected {
		Expect(err).To(HaveOccurred())
	} else {
		Expect(err).To(BeNil())
	}
},
	Entry("200 Error", 200, false),
	Entry("400 Error", 400, true),
	Entry("401 Error", 401, true),
	Entry("403 Error", 403, true),
	Entry("404 Error", 404, true),
)

var _ = Describe("getTemplate", func() {
	var params DeployGatewayParams

	BeforeEach(func() {
		params = DeployGatewayParams{
			SkuName:              "WAF_v2",
			Zones:                []string{"1", "2"},
			EnableHTTP2:          true,
			AutoscaleMinReplicas: 2,
			AutoscaleMaxReplicas: 10,
		}
	})

	It("should return a valid ARM template structure", func() {
		template := getTemplate(params)

		// Verify the template is not nil and contains expected top-level keys
		Expect(template).ToNot(BeNil())
		Expect(template).To(HaveKey("$schema"))
		Expect(template).To(HaveKey("contentVersion"))
		Expect(template).To(HaveKey("parameters"))
		Expect(template).To(HaveKey("variables"))
		Expect(template).To(HaveKey("resources"))
		Expect(template).To(HaveKey("outputs"))
	})

	It("should have correct schema and content version", func() {
		template := getTemplate(params)

		Expect(template["$schema"]).To(Equal("https://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#"))
		Expect(template["contentVersion"]).To(Equal("1.0.0.0"))
	})

	It("should contain expected parameters", func() {
		template := getTemplate(params)

		parameters, ok := template["parameters"].(map[string]interface{})
		Expect(ok).To(BeTrue())
		Expect(parameters).To(HaveKey("applicationGatewayName"))
		Expect(parameters).To(HaveKey("applicationGatewaySubnetId"))
		Expect(parameters).To(HaveKey("applicationGatewaySku"))

		// Verify applicationGatewayName parameter structure
		appGwName, ok := parameters["applicationGatewayName"].(map[string]interface{})
		Expect(ok).To(BeTrue())
		Expect(appGwName).To(HaveKey("defaultValue"))
		Expect(appGwName).To(HaveKey("type"))
		Expect(appGwName["defaultValue"]).To(Equal("appgw"))
		Expect(appGwName["type"]).To(Equal("string"))

		// Verify applicationGatewaySku parameter has allowed values
		appGwSku, ok := parameters["applicationGatewaySku"].(map[string]interface{})
		Expect(ok).To(BeTrue())
		Expect(appGwSku).To(HaveKey("allowedValues"))
		allowedValues, ok := appGwSku["allowedValues"].([]interface{})
		Expect(ok).To(BeTrue())
		Expect(allowedValues).To(ContainElement("Standard_v2"))
		Expect(allowedValues).To(ContainElement("WAF_v2"))
	})

	It("should contain expected variables", func() {
		template := getTemplate(params)

		variables, ok := template["variables"].(map[string]interface{})
		Expect(ok).To(BeTrue())
		Expect(variables).To(HaveKey("resgpguid"))
		Expect(variables).To(HaveKey("vnetName"))
		Expect(variables).To(HaveKey("applicationGatewayPublicIpName"))
		Expect(variables).To(HaveKey("applicationGatewayPublicIpId"))
		Expect(variables).To(HaveKey("applicationGatewayId"))
		Expect(variables).To(HaveKey("webApplicationFirewallConfiguration"))
	})

	It("should contain expected resources", func() {
		template := getTemplate(params)

		resources, ok := template["resources"].([]interface{})
		Expect(ok).To(BeTrue())
		Expect(resources).To(HaveLen(2))

		// Verify Public IP resource
		publicIPResource := resources[0].(map[string]interface{})
		Expect(publicIPResource["type"]).To(Equal("Microsoft.Network/publicIPAddresses"))
		Expect(publicIPResource["apiVersion"]).To(Equal("2018-11-01"))

		// Verify Application Gateway resource
		appGwResource := resources[1].(map[string]interface{})
		Expect(appGwResource["type"]).To(Equal("Microsoft.Network/applicationGateways"))
		Expect(appGwResource["apiVersion"]).To(Equal("2018-11-01"))

		// Verify Application Gateway has required tags
		appGwProperties := appGwResource["properties"].(map[string]interface{})
		Expect(appGwProperties).To(HaveKey("sku"))
		Expect(appGwProperties).To(HaveKey("gatewayIPConfigurations"))
		Expect(appGwProperties).To(HaveKey("frontendIPConfigurations"))
		Expect(appGwProperties).To(HaveKey("frontendPorts"))
		Expect(appGwProperties).To(HaveKey("backendAddressPools"))
		Expect(appGwProperties).To(HaveKey("httpListeners"))
		Expect(appGwProperties).To(HaveKey("backendHttpSettingsCollection"))
		Expect(appGwProperties).To(HaveKey("requestRoutingRules"))

		// Verify tags
		tags := appGwResource["tags"].(map[string]interface{})
		Expect(tags["managed-by-k8s-ingress"]).To(Equal("true"))
		Expect(tags["created-by"]).To(Equal("ingress-appgw"))
	})

	It("should contain expected outputs", func() {
		template := getTemplate(params)

		outputs, ok := template["outputs"].(map[string]interface{})
		Expect(ok).To(BeTrue())
		Expect(outputs).To(HaveKey("subscriptionId"))
		Expect(outputs).To(HaveKey("resourceGroupName"))
		Expect(outputs).To(HaveKey("applicationGatewayName"))

		// Verify output types
		subId := outputs["subscriptionId"].(map[string]interface{})
		Expect(subId["type"]).To(Equal("string"))

		resGroup := outputs["resourceGroupName"].(map[string]interface{})
		Expect(resGroup["type"]).To(Equal("string"))

		appGwName := outputs["applicationGatewayName"].(map[string]interface{})
		Expect(appGwName["type"]).To(Equal("string"))
	})

	It("should return valid JSON that can be marshaled", func() {
		template := getTemplate(params)

		// The template should be marshalable back to JSON
		jsonBytes, err := json.Marshal(template)
		Expect(err).To(BeNil())
		Expect(jsonBytes).ToNot(BeEmpty())

		// And it should be unmarshalable again (but don't compare exact equality due to type conversions)
		var unmarshaled map[string]interface{}
		err = json.Unmarshal(jsonBytes, &unmarshaled)
		Expect(err).To(BeNil())

		// Verify key structure is preserved
		Expect(unmarshaled).To(HaveKey("$schema"))
		Expect(unmarshaled).To(HaveKey("contentVersion"))
		Expect(unmarshaled).To(HaveKey("parameters"))
		Expect(unmarshaled).To(HaveKey("variables"))
		Expect(unmarshaled).To(HaveKey("resources"))
		Expect(unmarshaled).To(HaveKey("outputs"))
	})

	Context("when using autoscaling", func() {
		It("should add autoscale configuration and remove static capacity", func() {
			params := DeployGatewayParams{
				SkuName:              "Standard_v2",
				AutoscaleMinReplicas: 3,
				AutoscaleMaxReplicas: 15,
			}

			template := getTemplate(params)
			resources := template["resources"].([]interface{})
			appGwResource := resources[1].(map[string]interface{})
			appGwProperties := appGwResource["properties"].(map[string]interface{})

			// Should have autoscale configuration
			Expect(appGwProperties).To(HaveKey("autoscaleConfiguration"))
			autoscaleConfig := appGwProperties["autoscaleConfiguration"].(map[string]interface{})
			Expect(autoscaleConfig["minCapacity"]).To(Equal(int32(3)))
			Expect(autoscaleConfig["maxCapacity"]).To(Equal(int32(15)))

			// Should not have static capacity
			sku := appGwProperties["sku"].(map[string]interface{})
			Expect(sku).ToNot(HaveKey("capacity"))
		})

		It("should keep static capacity when autoscaling is not configured", func() {
			params := DeployGatewayParams{
				SkuName: "Standard_v2",
				// No autoscale replicas set
			}

			template := getTemplate(params)
			resources := template["resources"].([]interface{})
			appGwResource := resources[1].(map[string]interface{})
			appGwProperties := appGwResource["properties"].(map[string]interface{})

			// Should not have autoscale configuration
			Expect(appGwProperties).ToNot(HaveKey("autoscaleConfiguration"))

			// Should have static capacity (JSON unmarshaling converts numbers to float64)
			sku := appGwProperties["sku"].(map[string]interface{})
			Expect(sku).To(HaveKey("capacity"))
			Expect(sku["capacity"]).To(Equal(float64(2)))
		})
	})

	Context("when setting zones", func() {
		It("should add zones when specified", func() {
			params := DeployGatewayParams{
				Zones: []string{"1", "2", "3"},
			}

			template := getTemplate(params)
			resources := template["resources"].([]interface{})
			appGwResource := resources[1].(map[string]interface{})

			Expect(appGwResource).To(HaveKey("zones"))
			zones := appGwResource["zones"].([]string)
			Expect(zones).To(Equal([]string{"1", "2", "3"}))
		})

		It("should not add zones when not specified", func() {
			params := DeployGatewayParams{
				// Zones not set
			}

			template := getTemplate(params)
			resources := template["resources"].([]interface{})
			appGwResource := resources[1].(map[string]interface{})

			Expect(appGwResource).ToNot(HaveKey("zones"))
		})
	})

	Context("when enabling HTTP/2", func() {
		It("should enable HTTP/2 when flag is true", func() {
			params := DeployGatewayParams{
				EnableHTTP2: true,
			}

			template := getTemplate(params)
			resources := template["resources"].([]interface{})
			appGwResource := resources[1].(map[string]interface{})
			appGwProperties := appGwResource["properties"].(map[string]interface{})

			Expect(appGwProperties).To(HaveKey("enableHttp2"))
			Expect(appGwProperties["enableHttp2"]).To(BeTrue())
		})

		It("should not enable HTTP/2 when flag is false", func() {
			params := DeployGatewayParams{
				EnableHTTP2: false,
			}

			template := getTemplate(params)
			resources := template["resources"].([]interface{})
			appGwResource := resources[1].(map[string]interface{})
			appGwProperties := appGwResource["properties"].(map[string]interface{})

			Expect(appGwProperties).ToNot(HaveKey("enableHttp2"))
		})
	})

	Context("when setting private IP", func() {
		It("should add private IP when specified", func() {
			params := DeployGatewayParams{
				PrivateIP: "10.0.0.1",
			}

			template := getTemplate(params)
			resources := template["resources"].([]interface{})
			appGwResource := resources[1].(map[string]interface{})
			appGwProperties := appGwResource["properties"].(map[string]interface{})

			Expect(appGwProperties).To(HaveKey("frontendIPConfigurations"))
			frontendIPConfigurations := appGwProperties["frontendIPConfigurations"].([]interface{})
			Expect(frontendIPConfigurations).To(HaveLen(2))
		})
	})

	Context("when setting no public IP", func() {
		It("should add no public IP when specified", func() {
			params := DeployGatewayParams{
				NoPublicIP: true,
				PrivateIP:  "10.0.0.1",
			}

			template := getTemplate(params)
			resources := template["resources"].([]interface{})
			Expect(resources).To(HaveLen(1)) // no public IP resource
			appGwResource := resources[0].(map[string]interface{})
			appGwProperties := appGwResource["properties"].(map[string]interface{})

			Expect(appGwProperties).To(HaveKey("frontendIPConfigurations"))
			frontendIPConfigurations := appGwProperties["frontendIPConfigurations"].([]interface{})
			Expect(frontendIPConfigurations).To(HaveLen(1))
			Expect(frontendIPConfigurations[0].(map[string]interface{})["name"]).To(Equal("appGatewayFrontendPrivateIP"))
			Expect(frontendIPConfigurations[0].(map[string]interface{})["properties"].(map[string]interface{})["privateIPAddress"]).To(Equal("10.0.0.1"))
			Expect(frontendIPConfigurations[0].(map[string]interface{})["properties"].(map[string]interface{})["privateIPAllocationMethod"]).To(Equal("Static"))
			Expect(frontendIPConfigurations[0].(map[string]interface{})["properties"].(map[string]interface{})["subnet"].(map[string]interface{})["id"]).To(Equal("[parameters('applicationGatewaySubnetId')]"))
		})
	})
})
