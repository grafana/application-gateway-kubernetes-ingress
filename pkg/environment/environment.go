// -------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// --------------------------------------------------------------------------------------------

package environment

import (
	"os"
	"regexp"
	"strconv"
	"strings"

	"k8s.io/klog/v2"

	"github.com/Azure/application-gateway-kubernetes-ingress/pkg/azure"
	"github.com/Azure/application-gateway-kubernetes-ingress/pkg/controllererrors"
)

const (
	// CloudProviderConfigLocationVarName is an environment variable name. This file is available on azure cluster.
	CloudProviderConfigLocationVarName = "AZURE_CLOUD_PROVIDER_LOCATION"

	// ClientIDVarName is an environment variable which stores the client id provided through user assigned identity
	ClientIDVarName = "AZURE_CLIENT_ID"

	// SubscriptionIDVarName is the name of the APPGW_SUBSCRIPTION_ID
	SubscriptionIDVarName = "APPGW_SUBSCRIPTION_ID"

	// ResourceGroupNameVarName is the name of the APPGW_RESOURCE_GROUP
	ResourceGroupNameVarName = "APPGW_RESOURCE_GROUP"

	// AppGwNameVarName is the name of the APPGW_NAME
	AppGwNameVarName = "APPGW_NAME"

	// AppGwSubnetNameVarName is the name of the APPGW_SUBNET_NAME
	AppGwSubnetNameVarName = "APPGW_SUBNET_NAME"

	// AppGwSubnetPrefixVarName is the name of the APPGW_SUBNET_PREFIX
	AppGwSubnetPrefixVarName = "APPGW_SUBNET_PREFIX"

	// AppGwResourceIDVarName is the name of the APPGW_RESOURCE_ID
	AppGwResourceIDVarName = "APPGW_RESOURCE_ID"

	// AppGwSubnetIDVarName is the name of the APPGW_SUBNET_ID
	AppGwSubnetIDVarName = "APPGW_SUBNET_ID"

	// AppGwSkuVarName is the sku of the AGW
	AppGwSkuVarName = "APPGW_SKU_NAME"

	// AppGwZonesVarName is the name of the APPGW_ZONES
	AppGwZonesVarName = "APPGW_ZONES"

	// AppGwEnableHTTP2VarName is the name of the APPGW_ENABLE_HTTP2
	AppGwEnableHTTP2VarName = "APPGW_ENABLE_HTTP2"

	// AppGwAutoscaleMinReplicasVarName is the name of the APPGW_AUTOSCALE_MIN_REPLICAS
	AppGwAutoscaleMinReplicasVarName = "APPGW_AUTOSCALE_MIN_REPLICAS"

	// AppGwAutoscaleMaxReplicasVarName is the name of the APPGW_AUTOSCALE_MAX_REPLICAS
	AppGwAutoscaleMaxReplicasVarName = "APPGW_AUTOSCALE_MAX_REPLICAS"

	// FindPrivateIPVarName is the name of the APPGW_FIND_PRIVATE_IP
	FindPrivateIPVarName = "APPGW_FIND_PRIVATE_IP"

	// NoPublicIPVarName is the name of the APPGW_NO_PUBLIC_IP
	NoPublicIPVarName = "APPGW_NO_PUBLIC_IP"

	// AuthLocationVarName is the name of the AZURE_AUTH_LOCATION
	AuthLocationVarName = "AZURE_AUTH_LOCATION"

	// WatchNamespaceVarName is the name of the KUBERNETES_WATCHNAMESPACE
	WatchNamespaceVarName = "KUBERNETES_WATCHNAMESPACE"

	// UsePrivateIPVarName is the name of the USE_PRIVATE_IP
	UsePrivateIPVarName = "USE_PRIVATE_IP"

	// VerbosityLevelVarName sets the level of klog verbosity should the CLI argument be blank
	VerbosityLevelVarName = "APPGW_VERBOSITY_LEVEL"

	// EnableBrownfieldDeploymentVarName is a feature flag enabling observation of {Managed,Prohibited}Target CRDs
	EnableBrownfieldDeploymentVarName = "APPGW_ENABLE_SHARED_APPGW"

	// EnableIstioIntegrationVarName is a feature flag enabling observation of Istio specific CRDs
	EnableIstioIntegrationVarName = "APPGW_ENABLE_ISTIO_INTEGRATION"

	// EnableSaveConfigToFileVarName is a feature flag, which enables saving the App Gwy config to disk.
	EnableSaveConfigToFileVarName = "APPGW_ENABLE_SAVE_CONFIG_TO_FILE"

	// EnablePanicOnPutErrorVarName is a feature flag.
	EnablePanicOnPutErrorVarName = "APPGW_ENABLE_PANIC_ON_PUT_ERROR"

	// EnableDeployAppGatewayVarName is a feature flag.
	EnableDeployAppGatewayVarName = "APPGW_ENABLE_DEPLOY"

	// HTTPServicePortVarName is an environment variable name.
	HTTPServicePortVarName = "HTTP_SERVICE_PORT"

	// AGICPodNameVarName is an environment variable name.
	AGICPodNameVarName = "AGIC_POD_NAME"

	// AGICPodNamespaceVarName is an environment variable name.
	AGICPodNamespaceVarName = "AGIC_POD_NAMESPACE"

	// UseManagedIdentityForPodVarName is an environment variable name.
	UseManagedIdentityForPodVarName = "USE_MANAGED_IDENTITY_FOR_POD"

	// AttachWAFPolicyToListenerVarName is an environment variable name.
	AttachWAFPolicyToListenerVarName = "ATTACH_WAF_POLICY_TO_LISTENER"

	// HostedOnUnderlayVarName  is an environment variable name.
	HostedOnUnderlayVarName = "HOSTED_ON_UNDERLAY"

	// ReconcilePeriodSecondsVarName is an environment variable to control reconcile period for the AGIC.
	ReconcilePeriodSecondsVarName = "RECONCILE_PERIOD_SECONDS"

	// IngressClassVarName is an environment variable
	IngressClassVarName = "INGRESS_CLASS"

	// IngressClassResourceEnabledVarName is an environment variable to enable V1 Ingress class.
	IngressClassResourceEnabledVarName = "INGRESS_CLASS_RESOURCE_ENABLED"

	// IngressClassResourceNameVarName is an environment variable which specifies the name of the ingress class object to watch.
	IngressClassResourceNameVarName = "INGRESS_CLASS_RESOURCE_NAME"

	// IngressClassResourceDefaultVarName is an environment variable to enable AGIC as default ingress.
	IngressClassResourceDefaultVarName = "INGRESS_CLASS_RESOURCE_DEFAULT"

	// IngressClassControllerNameVarName is an environment variable to specify controller class.
	IngressClassControllerNameVarName = "INGRESS_CLASS_RESOURCE_CONTROLLER"

	// MultiClusterModeVarName is an environment variable to control whether AGIC monitors Ingresses or MutliClusterIngresses
	MultiClusterModeVarName = "MULTI_CLUSTER_MODE"

	// AddonModeVarName is an environment variable to inform if the controller is running as an addon.
	AddonModeVarName = "ADDON_MODE"

	// IgnoreCRDsVarName is an environment variable to ignore CRDs.
	IgnoreCRDsVarName = "IGNORE_CRDS"
)

const (
	//DefaultIngressClassController defines the default app gateway ingress value
	DefaultIngressClassController = "azure/application-gateway"

	//DefaultIngressClassResourceName defines the default app gateway ingress class object name
	DefaultIngressClassResourceName = "azure-application-gateway"
)

var (
	portNumberValidator = regexp.MustCompile(`^[0-9]{4,5}$`)
	skuValidator        = regexp.MustCompile(`WAF_v2|Standard_v2`)
	boolValidator       = regexp.MustCompile(`^(?i)(true|false)$`)
)

// EnvVariables is a struct storing values for environment variables.
type EnvVariables struct {
	CloudProviderConfigLocation string
	ClientID                    string
	SubscriptionID              string
	ResourceGroupName           string
	AppGwName                   string
	AppGwSubnetName             string
	AppGwSubnetPrefix           string
	AppGwResourceID             string
	AppGwSubnetID               string
	AppGwSkuName                string
	AppGwZones                  []string
	AppGwEnableHTTP2            bool
	AppGwAutoscaleMinReplicas   int32
	AppGwAutoscaleMaxReplicas   int32
	AppGwFindPrivateIP          bool
	AppGwNoPublicIP             bool
	AuthLocation                string
	IngressClass                string
	IngressClassControllerName  string
	IngressClassResourceEnabled bool
	IngressClassResourceName    string
	IngressClassResourceDefault bool
	WatchNamespace              string
	UsePrivateIP                bool
	VerbosityLevel              string
	AGICPodName                 string
	AGICPodNamespace            string
	EnableBrownfieldDeployment  bool
	EnableIstioIntegration      bool
	EnableSaveConfigToFile      bool
	EnablePanicOnPutError       bool
	EnableDeployAppGateway      bool
	UseManagedIdentityForPod    bool
	HTTPServicePort             string
	AttachWAFPolicyToListener   bool
	HostedOnUnderlay            bool
	ReconcilePeriodSeconds      string
	MultiClusterMode            bool
	AddonMode                   bool
	IgnoreCRDs                  bool
}

// Consolidate sets defaults and missing values using cpConfig
func (env *EnvVariables) Consolidate(cpConfig *azure.CloudProviderConfig) {
	// adjust env variable
	if env.AppGwResourceID != "" {
		subscriptionID, resourceGroupName, applicationGatewayName := azure.ParseResourceID(env.AppGwResourceID)
		env.SubscriptionID = string(subscriptionID)
		env.ResourceGroupName = string(resourceGroupName)
		env.AppGwName = string(applicationGatewayName)
	}

	// Set using cloud provider config
	if cpConfig != nil {
		if env.SubscriptionID == "" {
			env.SubscriptionID = string(cpConfig.SubscriptionID)
		}

		if env.ResourceGroupName == "" {
			env.ResourceGroupName = string(cpConfig.ResourceGroup)
		}
	}

	// Set defaults
	if env.AppGwSubnetName == "" {
		env.AppGwSubnetName = env.AppGwName + "-subnet"
	}

	if env.IngressClass != "" {
		env.IngressClassControllerName = env.IngressClass
	}

	if env.IngressClassControllerName == "" {
		env.IngressClassControllerName = DefaultIngressClassController
	}

	if env.IngressClassResourceName == "" {
		env.IngressClassResourceName = DefaultIngressClassResourceName
	}
}

// GetEnv returns values for defined environment variables for Ingress Controller.
func GetEnv() EnvVariables {
	usePrivateIP, _ := strconv.ParseBool(os.Getenv(UsePrivateIPVarName))
	findPrivateIP, _ := strconv.ParseBool(os.Getenv(FindPrivateIPVarName))
	noPublicIP, _ := strconv.ParseBool(os.Getenv(NoPublicIPVarName))
	multiClusterMode, _ := strconv.ParseBool(os.Getenv(MultiClusterModeVarName))
	appGwAutoscaleMinReplicas, _ := strconv.ParseInt(os.Getenv(AppGwAutoscaleMinReplicasVarName), 10, 32)
	appGwAutoscaleMaxReplicas, _ := strconv.ParseInt(os.Getenv(AppGwAutoscaleMaxReplicasVarName), 10, 32)

	env := EnvVariables{
		CloudProviderConfigLocation: os.Getenv(CloudProviderConfigLocationVarName),
		ClientID:                    os.Getenv(ClientIDVarName),
		SubscriptionID:              os.Getenv(SubscriptionIDVarName),
		ResourceGroupName:           os.Getenv(ResourceGroupNameVarName),
		AppGwName:                   os.Getenv(AppGwNameVarName),
		AppGwSubnetName:             os.Getenv(AppGwSubnetNameVarName),
		AppGwSubnetPrefix:           os.Getenv(AppGwSubnetPrefixVarName),
		AppGwResourceID:             os.Getenv(AppGwResourceIDVarName),
		AppGwSubnetID:               os.Getenv(AppGwSubnetIDVarName),
		AppGwSkuName:                GetEnvironmentVariable(AppGwSkuVarName, "Standard_v2", skuValidator),
		AppGwZones:                  strings.Split(os.Getenv(AppGwZonesVarName), ","),
		AppGwEnableHTTP2:            GetEnvironmentVariable(AppGwEnableHTTP2VarName, "false", boolValidator) == "true",
		AppGwAutoscaleMinReplicas:   int32(appGwAutoscaleMinReplicas),
		AppGwAutoscaleMaxReplicas:   int32(appGwAutoscaleMaxReplicas),
		AppGwFindPrivateIP:          findPrivateIP,
		AppGwNoPublicIP:             noPublicIP,
		AuthLocation:                os.Getenv(AuthLocationVarName),
		IngressClass:                os.Getenv(IngressClassVarName),
		IngressClassResourceEnabled: GetEnvironmentVariable(IngressClassResourceEnabledVarName, "false", boolValidator) == "true",
		IngressClassResourceName:    os.Getenv(IngressClassResourceNameVarName),
		IngressClassResourceDefault: GetEnvironmentVariable(IngressClassResourceDefaultVarName, "false", boolValidator) == "true",
		IngressClassControllerName:  os.Getenv(IngressClassControllerNameVarName),
		WatchNamespace:              os.Getenv(WatchNamespaceVarName),
		UsePrivateIP:                usePrivateIP,
		VerbosityLevel:              os.Getenv(VerbosityLevelVarName),
		AGICPodName:                 os.Getenv(AGICPodNameVarName),
		AGICPodNamespace:            os.Getenv(AGICPodNamespaceVarName),
		EnableBrownfieldDeployment:  GetEnvironmentVariable(EnableBrownfieldDeploymentVarName, "false", boolValidator) == "true",
		EnableIstioIntegration:      GetEnvironmentVariable(EnableIstioIntegrationVarName, "false", boolValidator) == "true",
		EnableSaveConfigToFile:      GetEnvironmentVariable(EnableSaveConfigToFileVarName, "false", boolValidator) == "true",
		EnablePanicOnPutError:       GetEnvironmentVariable(EnablePanicOnPutErrorVarName, "false", boolValidator) == "true",
		EnableDeployAppGateway:      GetEnvironmentVariable(EnableDeployAppGatewayVarName, "false", boolValidator) == "true",
		UseManagedIdentityForPod:    GetEnvironmentVariable(UseManagedIdentityForPodVarName, "false", boolValidator) == "true",
		HTTPServicePort:             GetEnvironmentVariable(HTTPServicePortVarName, "8123", portNumberValidator),
		AttachWAFPolicyToListener:   GetEnvironmentVariable(AttachWAFPolicyToListenerVarName, "false", boolValidator) == "true",
		HostedOnUnderlay:            GetEnvironmentVariable(HostedOnUnderlayVarName, "false", boolValidator) == "true",
		ReconcilePeriodSeconds:      os.Getenv(ReconcilePeriodSecondsVarName),
		MultiClusterMode:            multiClusterMode,
		AddonMode:                   GetEnvironmentVariable(AddonModeVarName, "false", boolValidator) == "true",
		IgnoreCRDs:                  GetEnvironmentVariable(IgnoreCRDsVarName, "false", boolValidator) == "true",
	}

	return env
}

// ValidateEnv validates environment variables.
func ValidateEnv(env EnvVariables) error {
	if env.EnableDeployAppGateway {
		// we should not allow applicationGatewayID in create case
		if len(env.AppGwResourceID) != 0 {
			return controllererrors.NewError(
				controllererrors.ErrorNotAllowedApplicationGatewayID,
				"Please provide provide APPGW_NAME (helm var name: .appgw.name) instead of APPGW_RESOURCE_ID (helm var name: .appgw.applicationGatewayID). "+
					"You can also provided APPGW_SUBSCRIPTION_ID and APPGW_RESOURCE_GROUP",
			)
		}

		// if deploy is true, we need applicationGatewayName
		if len(env.AppGwName) == 0 {
			return controllererrors.NewError(
				controllererrors.ErrorMissingApplicationGatewayName,
				"Missing required Environment variables: AGIC requires APPGW_NAME (helm var name: appgw.name) to deploy Application Gateway",
			)
		}

		// we need one of subnetID and subnetPrefix. We generate a subnetName if it is not provided.
		if len(env.AppGwSubnetID) == 0 && len(env.AppGwSubnetPrefix) == 0 {
			// when create is true, then either we should have env.AppGwSubnetID or env.AppGwSubnetPrefix
			return controllererrors.NewError(
				controllererrors.ErrorMissingSubnetInfo,
				"Missing required Environment variables: "+
					"AGIC requires APPGW_SUBNET_PREFIX (helm var name: appgw.subnetPrefix) or APPGW_SUBNET_ID (helm var name: appgw.subnetID) of an existing subnet. "+
					"If subnetPrefix is specified, AGIC will look up a subnet with matching address prefix in the AKS cluster vnet. "+
					"If a subnet is not found, then a new subnet will be created. This will be used to deploy the Application Gateway",
			)

		}
	} else {
		// if deploy is false, we need one of appgw name or resource id
		if len(env.AppGwName) == 0 && len(env.AppGwResourceID) == 0 {
			return controllererrors.NewError(
				controllererrors.ErrorMissingApplicationGatewayNameOrApplicationGatewayID,
				"Missing required Environment variables: "+
					"Provide atleast provide APPGW_NAME (helm var name: .appgw.name) or APPGW_RESOURCE_ID (helm var name: .appgw.applicationGatewayID). "+
					"If providing APPGW_NAME, You can also provided APPGW_SUBSCRIPTION_ID (helm var name: .appgw.subscriptionId) and APPGW_RESOURCE_GROUP (helm var name: .appgw.resourceGroup)",
			)
		}
	}

	if env.WatchNamespace == "" {
		klog.V(1).Infof("%s is not set. Watching all available namespaces.", WatchNamespaceVarName)
	}

	if env.ReconcilePeriodSeconds != "" {
		reconcilePeriodSeconds, err := strconv.Atoi(env.ReconcilePeriodSeconds)
		if err != nil {
			return controllererrors.NewErrorWithInnerError(
				controllererrors.ErrorInvalidReconcilePeriod,
				err,
				"Please make sure that RECONCILE_PERIOD_SECONDS (helm var name: .reconcilePeriodSeconds) is an integer. Range: (30 - 300)",
			)
		}

		if reconcilePeriodSeconds < 30 || reconcilePeriodSeconds > 300 {
			return controllererrors.NewError(
				controllererrors.ErrorInvalidReconcilePeriod,
				"Please make sure that RECONCILE_PERIOD_SECONDS (helm var name: .reconcilePeriodSeconds) is an integer. Range: (30 - 300)",
			)
		}
	}

	if env.AppGwAutoscaleMinReplicas > 0 && env.AppGwAutoscaleMaxReplicas == 0 {
		return controllererrors.NewError(
			controllererrors.ErrorInvalidAutoscaleReplicas,
			"Please make sure that APPGW_AUTOSCALE_MAX_REPLICAS (helm var name: .appgw.autoscaleMaxReplicas) is greater than 0 if APPGW_AUTOSCALE_MIN_REPLICAS (helm var name: .appgw.autoscaleMinReplicas) is greater than 0",
		)
	}

	if env.AppGwAutoscaleMaxReplicas > 0 && env.AppGwAutoscaleMinReplicas == 0 {
		return controllererrors.NewError(
			controllererrors.ErrorInvalidAutoscaleReplicas,
			"Please make sure that APPGW_AUTOSCALE_MIN_REPLICAS (helm var name: .appgw.autoscaleMinReplicas) is greater than 0 if APPGW_AUTOSCALE_MAX_REPLICAS (helm var name: .appgw.autoscaleMaxReplicas) is greater than 0",
		)
	}

	if env.AppGwAutoscaleMinReplicas > 0 && env.AppGwAutoscaleMaxReplicas < env.AppGwAutoscaleMinReplicas {
		return controllererrors.NewError(
			controllererrors.ErrorInvalidAutoscaleReplicas,
			"Please make sure that APPGW_AUTOSCALE_MAX_REPLICAS (helm var name: .appgw.autoscaleMaxReplicas) is greater than or equal to APPGW_AUTOSCALE_MIN_REPLICAS (helm var name: .appgw.autoscaleMinReplicas)",
		)
	}

	return nil
}

// GetEnvironmentVariable is an augmentation of os.Getenv, providing it with a default value.
func GetEnvironmentVariable(environmentVariable, defaultValue string, validator *regexp.Regexp) string {
	if value, ok := os.LookupEnv(environmentVariable); ok {
		if validator == nil {
			return value
		}
		if validator.MatchString(value) {
			return value
		}
		klog.Errorf("Environment variable %s contains a value which does not pass validation filter; Using default value: %s", environmentVariable, defaultValue)
	}
	return defaultValue
}
