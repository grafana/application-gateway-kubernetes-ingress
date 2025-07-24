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
