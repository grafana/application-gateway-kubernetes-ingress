// -------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// --------------------------------------------------------------------------------------------

package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"time"

	r "github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	n "github.com/Azure/azure-sdk-for-go/services/network/mgmt/2021-03-01/network"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/Azure/go-autorest/autorest/to"
	"k8s.io/klog/v2"

	"github.com/Azure/application-gateway-kubernetes-ingress/pkg/controllererrors"
	"github.com/Azure/application-gateway-kubernetes-ingress/pkg/utils"
	"github.com/Azure/application-gateway-kubernetes-ingress/pkg/version"
)

type DeployGatewayParams struct {
	SkuName              string
	Zones                []string
	EnableHTTP2          bool
	AutoscaleMinReplicas int32
	AutoscaleMaxReplicas int32
	PrivateIP            string
	FindPrivateIP        bool
	NoPublicIP           bool
}

// AzClient is an interface for client to Azure
type AzClient interface {
	SetAuthorizer(authorizer autorest.Authorizer)
	SetSender(sender autorest.Sender)
	SetDuration(retryDuration time.Duration)

	ApplyRouteTable(string, string) error
	WaitForGetAccessOnGateway(maxRetryCount int) error
	GetGateway() (n.ApplicationGateway, error)
	UpdateGateway(*n.ApplicationGateway) error
	DeployGatewayWithVnet(ResourceGroup, ResourceName, ResourceName, string, DeployGatewayParams) error
	DeployGatewayWithSubnet(string, DeployGatewayParams) error
	GetSubnet(string) (n.Subnet, error)
	GetAvailablePrivateIP(string) (*string, error)

	GetPublicIP(string) (n.PublicIPAddress, error)
}

type azClient struct {
	appGatewaysClient     n.ApplicationGatewaysClient
	publicIPsClient       n.PublicIPAddressesClient
	virtualNetworksClient n.VirtualNetworksClient
	subnetsClient         n.SubnetsClient
	routeTablesClient     n.RouteTablesClient
	groupsClient          r.GroupsClient
	deploymentsClient     r.DeploymentsClient
	clientID              string

	subscriptionID    SubscriptionID
	resourceGroupName ResourceGroup
	appGwName         ResourceName
	memoizedIPs       map[string]n.PublicIPAddress

	ctx context.Context
}

// NewAzClient returns an Azure Client
func NewAzClient(subscriptionID SubscriptionID, resourceGroupName ResourceGroup, appGwName ResourceName, uniqueUserAgentSuffix, clientID string) AzClient {
	settings, err := auth.GetSettingsFromEnvironment()
	if err != nil {
		return nil
	}

	userAgent := fmt.Sprintf("ingress-appgw/%s/%s", version.Version, uniqueUserAgentSuffix)
	az := &azClient{
		appGatewaysClient:     n.NewApplicationGatewaysClientWithBaseURI(settings.Environment.ResourceManagerEndpoint, string(subscriptionID)),
		publicIPsClient:       n.NewPublicIPAddressesClientWithBaseURI(settings.Environment.ResourceManagerEndpoint, string(subscriptionID)),
		virtualNetworksClient: n.NewVirtualNetworksClientWithBaseURI(settings.Environment.ResourceManagerEndpoint, string(subscriptionID)),
		subnetsClient:         n.NewSubnetsClientWithBaseURI(settings.Environment.ResourceManagerEndpoint, string(subscriptionID)),
		routeTablesClient:     n.NewRouteTablesClientWithBaseURI(settings.Environment.ResourceManagerEndpoint, string(subscriptionID)),
		groupsClient:          r.NewGroupsClientWithBaseURI(settings.Environment.ResourceManagerEndpoint, string(subscriptionID)),
		deploymentsClient:     r.NewDeploymentsClientWithBaseURI(settings.Environment.ResourceManagerEndpoint, string(subscriptionID)),
		clientID:              clientID,

		subscriptionID:    subscriptionID,
		resourceGroupName: resourceGroupName,
		appGwName:         appGwName,
		memoizedIPs:       make(map[string]n.PublicIPAddress),

		ctx: context.Background(),
	}

	if err := az.appGatewaysClient.AddToUserAgent(userAgent); err != nil {
		klog.Error("Error adding User Agent to App Gateway client: ", userAgent)
	}
	if err := az.publicIPsClient.AddToUserAgent(userAgent); err != nil {
		klog.Error("Error adding User Agent to Public IP client: ", userAgent)
	}
	if err := az.virtualNetworksClient.AddToUserAgent(userAgent); err != nil {
		klog.Error("Error adding User Agent to Virtual Networks client: ", userAgent)
	}
	if err := az.subnetsClient.AddToUserAgent(userAgent); err != nil {
		klog.Error("Error adding User Agent to Subnets client: ", userAgent)
	}
	if err := az.routeTablesClient.AddToUserAgent(userAgent); err != nil {
		klog.Error("Error adding User Agent to Route Tables client: ", userAgent)
	}
	if err := az.groupsClient.AddToUserAgent(userAgent); err != nil {
		klog.Error("Error adding User Agent to Groups client: ", userAgent)
	}
	if err := az.deploymentsClient.AddToUserAgent(userAgent); err != nil {
		klog.Error("Error adding User Agent to Deployments client: ", userAgent)
	}

	// increase the polling duration to 60 minutes
	az.appGatewaysClient.PollingDuration = 60 * time.Minute
	az.deploymentsClient.PollingDuration = 60 * time.Minute

	return az
}

func (az *azClient) SetAuthorizer(authorizer autorest.Authorizer) {
	az.appGatewaysClient.Authorizer = authorizer
	az.publicIPsClient.Authorizer = authorizer
	az.virtualNetworksClient.Authorizer = authorizer
	az.subnetsClient.Authorizer = authorizer
	az.routeTablesClient.Authorizer = authorizer
	az.groupsClient.Authorizer = authorizer
	az.deploymentsClient.Authorizer = authorizer
}

func (az *azClient) SetSender(sender autorest.Sender) {
	az.appGatewaysClient.Client.Sender = sender
}

func (az *azClient) SetDuration(retryDuration time.Duration) {
	az.appGatewaysClient.Client.RetryDuration = retryDuration
}

func (az *azClient) WaitForGetAccessOnGateway(maxRetryCount int) (err error) {
	klog.V(3).Info("Getting Application Gateway configuration.")
	err = utils.Retry(maxRetryCount, retryPause,
		func() (utils.Retriable, error) {
			response, err := az.appGatewaysClient.Get(az.ctx, string(az.resourceGroupName), string(az.appGwName))
			if err == nil {
				return utils.Retriable(true), nil
			}

			e := controllererrors.NewErrorWithInnerErrorf(
				controllererrors.ErrorGetApplicationGatewayError,
				err,
				"Failed fetching configuration for Application Gateway. Will retry in %v.", retryPause,
			)

			if response.Response.Response != nil {
				e = controllererrors.NewErrorWithInnerErrorf(
					controllererrors.ErrorApplicationGatewayUnexpectedStatusCode,
					err,
					"Unexpected status code '%d' while performing a GET on Application Gateway.", response.Response.StatusCode,
				)

				if response.Response.StatusCode == 404 {
					e.Code = controllererrors.ErrorApplicationGatewayNotFound
				}

				if response.Response.StatusCode == 403 {
					e.Code = controllererrors.ErrorApplicationGatewayForbidden

					clientID := "<agic-client-id>"
					if az.clientID != "" {
						clientID = az.clientID
					}

					groupID := ResourceGroupID(az.subscriptionID, az.resourceGroupName)
					applicationGatewayID := ApplicationGatewayID(az.subscriptionID, az.resourceGroupName, az.appGwName)
					roleAssignmentCmd := fmt.Sprintf("az role assignment create --role Reader --scope %s --assignee %s;"+
						" az role assignment create --role Contributor --scope %s --assignee %s",
						groupID,
						clientID,
						applicationGatewayID,
						clientID,
					)

					e.Message += fmt.Sprintf(" You can use '%s' to assign permissions."+
						" AGIC Identity needs at least 'Contributor' access to Application Gateway '%s' and 'Reader' access to Application Gateway's Resource Group '%s'.",
						roleAssignmentCmd,
						string(az.appGwName),
						string(az.resourceGroupName),
					)
				}
				if response.Response.StatusCode == 400 || response.Response.StatusCode == 401 {
					klog.Errorf("configuration error (bad request) or unauthorized error while performing a GET using the authorizer")
					klog.Errorf("stopping GET retries")
					return utils.Retriable(false), e
				}
			}

			klog.Errorf(e.Error())
			if controllererrors.IsErrorCode(e, controllererrors.ErrorApplicationGatewayNotFound) {
				return utils.Retriable(false), e
			}

			return utils.Retriable(true), e
		})

	return
}

func (az *azClient) GetGateway() (gateway n.ApplicationGateway, err error) {
	err = utils.Retry(retryCount, retryPause,
		func() (utils.Retriable, error) {
			gateway, err = az.appGatewaysClient.Get(az.ctx, string(az.resourceGroupName), string(az.appGwName))
			if err != nil {
				klog.Errorf("Error while getting application gateway '%s': %s", string(az.appGwName), err)
			}
			return utils.Retriable(true), err
		})
	return
}

func (az *azClient) UpdateGateway(appGwObj *n.ApplicationGateway) (err error) {
	appGwFuture, err := az.appGatewaysClient.CreateOrUpdate(az.ctx, string(az.resourceGroupName), string(az.appGwName), *appGwObj)
	if err != nil {
		return
	}

	if appGwFuture.PollingURL() != "" {
		klog.V(3).Infof("OperationID='%s'", GetOperationIDFromPollingURL(appGwFuture.PollingURL()))
	}

	// Wait until deployment finshes and save the error message
	err = appGwFuture.WaitForCompletionRef(az.ctx, az.appGatewaysClient.BaseClient.Client)
	return
}

func (az *azClient) GetPublicIP(resourceID string) (n.PublicIPAddress, error) {
	if ip, ok := az.memoizedIPs[resourceID]; ok {
		return ip, nil
	}

	_, resourceGroupName, publicIPName := ParseResourceID(resourceID)

	ip, err := az.publicIPsClient.Get(az.ctx, string(resourceGroupName), string(publicIPName), "")
	if err != nil {
		return n.PublicIPAddress{}, err
	}
	az.memoizedIPs[resourceID] = ip
	return ip, nil
}

func (az *azClient) ApplyRouteTable(subnetID string, routeTableID string) error {
	// Check if the route table exists
	_, routeTableResourceGroup, routeTableName := ParseResourceID(routeTableID)
	routeTable, err := az.routeTablesClient.Get(az.ctx, string(routeTableResourceGroup), string(routeTableName), "")

	// if route table is not found, then simply add a log and return no error. routeTable will always be initialized.
	if routeTable.Response.StatusCode == 404 {
		return nil
	}

	if err != nil {
		// no access or no route table
		return err
	}

	// Get subnet and check if it is already associated to a route table
	_, subnetResourceGroup, subnetVnetName, subnetName := ParseSubResourceID(subnetID)
	subnet, err := az.subnetsClient.Get(az.ctx, string(subnetResourceGroup), string(subnetVnetName), string(subnetName), "")
	if err != nil {
		return err
	}

	if subnet.RouteTable != nil {
		if *subnet.RouteTable.ID != routeTableID {
			klog.V(3).Infof("Skipping associating Application Gateway subnet '%s' with route table '%s' used by k8s cluster as it is already associated to route table '%s'.",
				subnetID,
				routeTableID,
				*subnet.SubnetPropertiesFormat.RouteTable.ID)
		} else {
			klog.V(3).Infof("Application Gateway subnet '%s' is associated with route table '%s' used by k8s cluster.",
				subnetID,
				routeTableID)
		}

		return nil
	}

	klog.Infof("Associating Application Gateway subnet '%s' with route table '%s' used by k8s cluster.", subnetID, routeTableID)
	subnet.RouteTable = &routeTable

	subnetFuture, err := az.subnetsClient.CreateOrUpdate(az.ctx, string(subnetResourceGroup), string(subnetVnetName), string(subnetName), subnet)
	if err != nil {
		return err
	}

	// Wait until deployment finshes and save the error message
	err = subnetFuture.WaitForCompletionRef(az.ctx, az.subnetsClient.BaseClient.Client)
	if err != nil {
		return err
	}

	return nil
}

func (az *azClient) GetSubnet(subnetID string) (subnet n.Subnet, err error) {
	_ = utils.Retry(retryCount, retryPause,
		func() (utils.Retriable, error) {
			_, subnetResourceGroup, subnetVnetName, subnetName := ParseSubResourceID(subnetID)
			subnet, err = az.subnetsClient.Get(az.ctx, string(subnetResourceGroup), string(subnetVnetName), string(subnetName), "")
			return utils.Retriable(true), err
		})

	return
}

// DeployGatewayWithVnet creates Application Gateway within the specifid VNet. Implements AzClient interface.
func (az *azClient) DeployGatewayWithVnet(resourceGroupName ResourceGroup, vnetName ResourceName, subnetName ResourceName, subnetPrefix string, params DeployGatewayParams) (err error) {
	vnet, err := az.getVnet(resourceGroupName, vnetName)
	if err != nil {
		return
	}

	klog.Infof("Checking the Vnet '%s' for a subnet with prefix '%s'.", vnetName, subnetPrefix)
	subnet, err := az.findSubnet(vnet, subnetName, subnetPrefix)
	if err != nil {
		if subnetPrefix == "" {
			klog.Infof("Unable to find a subnet with subnetName '%s'. Please provide subnetPrefix in order to allow AGIC to create a subnet in Vnet '%s'.", subnetName, vnetName)
			return
		}

		klog.Infof("Unable to find a subnet. Creating a subnet '%s' with prefix '%s' in Vnet '%s'.", subnetName, subnetPrefix, vnetName)
		subnet, err = az.createSubnet(vnet, subnetName, subnetPrefix)
		if err != nil {
			return
		}
	} else if subnet.SubnetPropertiesFormat != nil && (subnet.SubnetPropertiesFormat.Delegations == nil || (subnet.SubnetPropertiesFormat.Delegations != nil && len(*subnet.SubnetPropertiesFormat.Delegations) == 0)) {
		klog.Infof("Subnet '%s' is an existing subnet and subnet delegation to Application Gateway is not found, creating a delegation.", subnetName)
		subnet, err = az.createSubnet(vnet, subnetName, subnetPrefix)
		if err != nil {
			klog.Errorf("Backfill delegation to Application Gateway on existing subnet has failed. Please check the subnet '%s' in vnet '%s'.", subnetName, vnetName)
		}
	}

	err = az.DeployGatewayWithSubnet(*subnet.ID, params)
	return
}

// DeployGatewayWithSubnet creates Application Gateway within the specifid subnet. Implements AzClient interface.
func (az *azClient) DeployGatewayWithSubnet(subnetID string, params DeployGatewayParams) (err error) {
	klog.Infof("Deploying Gateway")

	// Check if group exists
	group, err := az.getGroup()
	if err != nil {
		return
	}
	klog.Infof("Using resource group: %v", *group.Name)

	if params.FindPrivateIP {
		// get private ip
		ip, err := az.GetAvailablePrivateIP(subnetID)
		if err != nil {
			return err
		}
		params.PrivateIP = *ip
		klog.Infof("Found available private ip: %s", *ip)
	}

	deploymentName := string(az.appGwName)
	klog.Infof("Starting ARM template deployment: %s", deploymentName)
	result, err := az.createDeployment(subnetID, params)
	if err != nil {
		return
	}
	if result.Name != nil {
		klog.Infof("Completed deployment %v: %v", deploymentName, result.Properties.ProvisioningState)
	} else {
		klog.Infof("Completed deployment %v (no data returned to SDK)", deploymentName)
	}

	return
}

// Create a resource group for the deployment.
func (az *azClient) getGroup() (group r.Group, err error) {
	utils.Retry(retryCount, retryPause,
		func() (utils.Retriable, error) {
			group, err = az.groupsClient.Get(az.ctx, string(az.resourceGroupName))
			if err != nil {
				klog.Errorf("Error while getting resource group '%s': %s", az.resourceGroupName, err)
			}
			return utils.Retriable(true), err
		})

	return
}

func (az *azClient) getVnet(resourceGroupName ResourceGroup, vnetName ResourceName) (vnet n.VirtualNetwork, err error) {
	utils.Retry(extendedRetryCount, retryPause,
		func() (utils.Retriable, error) {
			vnet, err = az.virtualNetworksClient.Get(az.ctx, string(resourceGroupName), string(vnetName), "")
			if err != nil {
				klog.Errorf("Error while getting virtual network '%s': %s", vnetName, err)
			}
			return utils.Retriable(true), err
		})

	return
}

func (az *azClient) findSubnet(vnet n.VirtualNetwork, subnetName ResourceName, subnetPrefix string) (subnet n.Subnet, err error) {
	for _, subnet := range *vnet.Subnets {
		if string(subnetName) == *subnet.Name && (subnetPrefix == "" || subnetPrefix == *subnet.AddressPrefix) {
			return subnet, nil
		}
	}
	err = controllererrors.NewErrorf(
		controllererrors.ErrorSubnetNotFound,
		"Unable to find subnet with matching subnetName %s and subnetPrefix %s in virtual network %s", subnetName, subnetPrefix, *vnet.ID,
	)
	return
}

func (az *azClient) createSubnet(vnet n.VirtualNetwork, subnetName ResourceName, subnetPrefix string) (subnet n.Subnet, err error) {
	_, resourceGroup, vnetName := ParseResourceID(*vnet.ID)
	subnet = n.Subnet{
		SubnetPropertiesFormat: &n.SubnetPropertiesFormat{
			AddressPrefix: &subnetPrefix,
			Delegations: &[]n.Delegation{
				{
					Name: to.StringPtr("Microsoft.Network/applicationGateways"),
					ServiceDelegationPropertiesFormat: &n.ServiceDelegationPropertiesFormat{
						ServiceName: to.StringPtr("Microsoft.Network/applicationGateways"),
					},
				},
			},
		},
	}
	subnetFuture, err := az.subnetsClient.CreateOrUpdate(az.ctx, string(resourceGroup), string(vnetName), string(subnetName), subnet)
	if err != nil {
		return
	}

	// Wait until deployment finshes and save the error message
	err = subnetFuture.WaitForCompletionRef(az.ctx, az.subnetsClient.BaseClient.Client)
	if err != nil {
		return
	}

	return az.subnetsClient.Get(az.ctx, string(resourceGroup), string(vnetName), string(subnetName), "")
}

// Create the deployment
func (az *azClient) createDeployment(subnetID string, params DeployGatewayParams) (deployment r.DeploymentExtended, err error) {
	template := getTemplate(params)
	if err != nil {
		return
	}
	templateParams := map[string]interface{}{
		"applicationGatewayName": map[string]string{
			"value": string(az.appGwName),
		},
		"applicationGatewaySubnetId": map[string]string{
			"value": subnetID,
		},
		"applicationGatewaySku": map[string]string{
			"value": params.SkuName,
		},
	}

	deploymentFuture, err := az.deploymentsClient.CreateOrUpdate(
		az.ctx,
		string(az.resourceGroupName),
		string(az.appGwName),
		r.Deployment{
			Properties: &r.DeploymentProperties{
				Template:   template,
				Parameters: templateParams,
				Mode:       r.DeploymentModeIncremental,
			},
		},
	)
	if err != nil {
		return
	}
	err = deploymentFuture.WaitForCompletionRef(az.ctx, az.deploymentsClient.BaseClient.Client)
	if err != nil {
		return
	}
	return deploymentFuture.Result(az.deploymentsClient)
}

func getTemplate(params DeployGatewayParams) map[string]interface{} {
	template := `
	{
		"$schema": "https://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#",
		"contentVersion": "1.0.0.0",
		"parameters": {
			"applicationGatewayName": {
				"defaultValue": "appgw",
				"type": "string",
				"metadata": {
					"description": "Name of the Application Gateway."
				}
			},
			"applicationGatewaySubnetId": {
				"type": "string",
				"metadata": {
					"description": "Resource Id of Subnet in which Application Gateway will be deployed."
				}
			},
			"applicationGatewaySku": {
				"allowedValues": [
					"Standard_v2",
					"WAF_v2"
				],
				"type": "string",
				"metadata": {
					"description": "The sku of the Application Gateway. Default: WAF_v2 (Detection mode). In order to further customize WAF, use azure portal or cli."
				}
			}
		},
		"variables": {
			"resgpguid": "[substring(replace(guid(resourceGroup().id), '-', ''), 0, 4)]",
			"vnetName": "[concat('virtualnetwork' , variables('resgpguid'))]",
			"applicationGatewayPublicIpName": "[concat(parameters('applicationGatewayName'), '-appgwpip')]",
			"applicationGatewayPublicIpId": "[resourceId('Microsoft.Network/publicIPAddresses',variables('applicationGatewayPublicIpName'))]",
			"applicationGatewayId": "[resourceId('Microsoft.Network/applicationGateways', parameters('applicationGatewayName'))]",
			"webApplicationFirewallConfiguration": {
			  "enabled": "true",
			  "firewallMode": "Detection"
			}
		},
		"resources": [
			{
				"type": "Microsoft.Network/publicIPAddresses",
				"name": "[variables('applicationGatewayPublicIpName')]",
				"apiVersion": "2018-11-01",
				"location": "[resourceGroup().location]",
				"sku": {
					"name": "Standard"
				},
				"properties": {
					"publicIPAllocationMethod": "Static"
				}
			},
			{
				"type": "Microsoft.Network/applicationGateways",
				"name": "[parameters('applicationGatewayName')]",
				"apiVersion": "2018-11-01",
				"location": "[resourceGroup().location]",
				"tags": {
					"managed-by-k8s-ingress": "true",
					"created-by": "ingress-appgw"
				},
				"properties": {
					"sku": {
						"name": "[parameters('applicationGatewaySku')]",
						"tier": "[parameters('applicationGatewaySku')]",
						"capacity": 2
					},
					"gatewayIPConfigurations": [
						{
							"name": "appGatewayIpConfig",
							"properties": {
								"subnet": {
									"id": "[parameters('applicationGatewaySubnetId')]"
								}
							}
						}
					],
					"frontendIPConfigurations": [
						{
							"name": "appGatewayFrontendIP",
							"properties": {
								"PublicIPAddress": {
									"id": "[variables('applicationGatewayPublicIpId')]"
								}
							}
						}
					],
					"frontendPorts": [
						{
							"name": "httpPort",
							"properties": {
								"Port": 80
							}
						},
						{
							"name": "httpsPort",
							"properties": {
								"Port": 443
							}
						}
					],
					"backendAddressPools": [
						{
							"name": "bepool",
							"properties": {
								"backendAddresses": []
							}
						}
					],
					"httpListeners": [
						{
							"name": "httpListener",
							"properties": {
								"protocol": "Http",
								"frontendPort": {
									"id": "[concat(variables('applicationGatewayId'), '/frontendPorts/httpPort')]"
								},
								"frontendIPConfiguration": {
									"id": "[concat(variables('applicationGatewayId'), '/frontendIPConfigurations/appGatewayFrontendIP')]"
								}
							}
						}
					],
					"backendHttpSettingsCollection": [
						{
							"name": "setting",
							"properties": {
								"port": 80,
								"protocol": "Http"
							}
						}
					],
					"requestRoutingRules": [
						{
							"name": "rule1",
							"properties": {
								"httpListener": {
									"id": "[concat(variables('applicationGatewayId'), '/httpListeners/httpListener')]"
								},
								"backendAddressPool": {
									"id": "[concat(variables('applicationGatewayId'), '/backendAddressPools/bepool')]"
								},
								"backendHttpSettings": {
									"id": "[concat(variables('applicationGatewayId'), '/backendHttpSettingsCollection/setting')]"
								}
							}
						}
					],
					"webApplicationFirewallConfiguration": "[if(equals(parameters('applicationGatewaySku'), 'WAF_v2'), variables('webApplicationFirewallConfiguration'), json('null'))]"
				},
				"dependsOn": [
					"[concat('Microsoft.Network/publicIPAddresses/', variables('applicationGatewayPublicIpName'))]"
				]
			}
		],
		"outputs": {
			"subscriptionId": {
				"type": "string",
				"value": "[subscription().subscriptionId]"
			},
			"resourceGroupName": {
				"type": "string",
				"value": "[resourceGroup().name]"
			},
			"applicationGatewayName": {
				"type": "string",
				"value": "[parameters('applicationGatewayName')]"
			}
		}
	}`

	contents := make(map[string]interface{})
	json.Unmarshal([]byte(template), &contents)

	// Apply customizations based on params
	resources := contents["resources"].([]interface{})
	appGwResource := resources[1].(map[string]interface{})
	appGwProperties := appGwResource["properties"].(map[string]interface{})
	sku := appGwProperties["sku"].(map[string]interface{})

	// Handle autoscaling configuration
	if params.AutoscaleMinReplicas > 0 && params.AutoscaleMaxReplicas > 0 {
		// Remove static capacity and add autoscale configuration
		delete(sku, "capacity")
		appGwProperties["autoscaleConfiguration"] = map[string]interface{}{
			"minCapacity": params.AutoscaleMinReplicas,
			"maxCapacity": params.AutoscaleMaxReplicas,
		}
	}

	// Add zones if specified
	if len(params.Zones) > 0 {
		appGwResource["zones"] = params.Zones
	}

	// Enable HTTP/2 if specified
	if params.EnableHTTP2 {
		appGwProperties["enableHttp2"] = true
	}

	// Add private IP if specified
	if params.PrivateIP != "" {
		frontendIPConfigurations := appGwProperties["frontendIPConfigurations"].([]interface{})
		frontendIPConfigurations = append(frontendIPConfigurations, map[string]interface{}{
			"name": "appGatewayFrontendPrivateIP",
			"properties": map[string]interface{}{
				"privateIPAddress":          params.PrivateIP,
				"privateIPAllocationMethod": "Static",
				"subnet": map[string]interface{}{
					"id": "[parameters('applicationGatewaySubnetId')]",
				},
			},
		})
		appGwProperties["frontendIPConfigurations"] = frontendIPConfigurations
	}

	if params.NoPublicIP {
		// 1. Remove Public IP from variables
		variables := contents["variables"].(map[string]interface{})
		delete(variables, "applicationGatewayPublicIpName")
		delete(variables, "applicationGatewayPublicIpId")

		var appGwResource map[string]interface{}

		// 2. Remove Public IP and dependsOn from resources
		var newResources []interface{}
		resources := contents["resources"].([]interface{})
		for _, resource := range resources {
			resMap := resource.(map[string]interface{})
			if resMap["type"] != "Microsoft.Network/publicIPAddresses" {
				newResources = append(newResources, resource)
				if resMap["type"] == "Microsoft.Network/applicationGateways" {
					appGwResource = resMap
				}
			}
		}
		contents["resources"] = newResources

		delete(appGwResource, "dependsOn")

		properties := appGwResource["properties"].(map[string]interface{})

		// 3. Remove public frontend IP config
		frontendIPConfigurations := properties["frontendIPConfigurations"].([]interface{})
		var newFrontendIPConfigurations []interface{}
		for _, feIPConfig := range frontendIPConfigurations {
			feIPConfigMap := feIPConfig.(map[string]interface{})
			if feIPConfigMap["name"] != "appGatewayFrontendIP" {
				newFrontendIPConfigurations = append(newFrontendIPConfigurations, feIPConfig)
			}
		}
		properties["frontendIPConfigurations"] = newFrontendIPConfigurations

		// 4. Update HTTP listener
		httpListeners := properties["httpListeners"].([]interface{})
		for _, listener := range httpListeners {
			listenerMap := listener.(map[string]interface{})
			listenerProps := listenerMap["properties"].(map[string]interface{})
			frontendIPConfig := listenerProps["frontendIPConfiguration"].(map[string]interface{})
			frontendIPConfig["id"] = "[concat(variables('applicationGatewayId'), '/frontendIPConfigurations/appGatewayFrontendPrivateIP')]"
		}
	}

	return contents
}

func (az *azClient) GetAvailablePrivateIP(subnetID string) (*string, error) {
	_, subnetResourceGroup, vnetName, subnetName := ParseSubResourceID(subnetID)

	// get the subnet
	subnet, err := az.subnetsClient.Get(az.ctx, string(subnetResourceGroup), string(vnetName), string(subnetName), "")
	if err != nil {
		return nil, err
	}

	// generate random list of IPs in the subnet
	availableIPs, err := generateRandomIPsInSubnet(subnet.AddressPrefix)
	if err != nil {
		return nil, err
	}

	// check each IP for availability using Azure API
	for _, ip := range availableIPs {
		klog.Infof("Checking IP availability for %s", ip)

		result, err := az.virtualNetworksClient.CheckIPAddressAvailability(az.ctx, string(subnetResourceGroup), string(vnetName), ip)
		if err != nil {
			klog.Infof("Error checking IP availability for %s: %v", ip, err)
			continue
		}

		if result.Available != nil && *result.Available {
			klog.V(3).Infof("Found available IP: %s", ip)
			return &ip, nil
		}
	}

	return nil, controllererrors.NewError(
		controllererrors.ErrorFindingAvailablePrivateIP, "No available private IP found in the subnet",
	)
}

func generateRandomIPsInSubnet(subnetAddressPrefix *string) ([]string, error) {
	if subnetAddressPrefix == nil {
		return nil, fmt.Errorf("subnet address prefix cannot be nil")
	}

	// get the first and last ip in the subnet
	firstIP, lastIP, err := getFirstAndLastIP(subnetAddressPrefix)
	if err != nil {
		return nil, err
	}

	// calculate total usable IPs (excluding network and broadcast)
	totalUsableIPs := lastIP - firstIP - 1
	if totalUsableIPs <= 0 {
		return nil, fmt.Errorf("subnet has no usable IP addresses")
	}

	// determine how many IPs we want to generate
	maxIPs := 50
	numIPsToGenerate := int(totalUsableIPs)
	if numIPsToGenerate > maxIPs {
		numIPsToGenerate = maxIPs
	}

	// generate random unique IPs
	usedIPs := make(map[uint32]bool)
	var ipStrings []string

	for len(ipStrings) < numIPsToGenerate {
		// generate random IP in range (excluding network and broadcast)
		randomOffset := rand.Intn(int(totalUsableIPs))
		randomIP := firstIP + 1 + uint32(randomOffset)

		// skip if we've already used this IP
		if usedIPs[randomIP] {
			continue
		}

		usedIPs[randomIP] = true
		ipStrings = append(ipStrings, longToIP(randomIP))
	}

	return ipStrings, nil
}

func getFirstAndLastIP(subnetAddressPrefix *string) (uint32, uint32, error) {
	if subnetAddressPrefix == nil {
		return 0, 0, fmt.Errorf("subnet address prefix cannot be nil")
	}

	// get the first and last ip in the subnet
	ip, ipNet, err := net.ParseCIDR(*subnetAddressPrefix)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid CIDR format: %v", err)
	}

	firstIP := ipToLong(ip)
	mask := ipNet.Mask
	lastIP := firstIP | (uint32((1<<(net.IPv4len*8))-1) ^ ipToLong(net.IP(mask)))

	return firstIP, lastIP, nil
}

func ipToLong(ip net.IP) uint32 {
	ip = ip.To4()
	return (uint32(ip[0]) << 24) | (uint32(ip[1]) << 16) | (uint32(ip[2]) << 8) | uint32(ip[3])
}

func longToIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}
