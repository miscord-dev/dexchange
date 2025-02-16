/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// DeXTokenSpec defines the desired state of DeXToken.
type DeXTokenSpec struct {
	// DeX is the configuration for the DeX Machine Auth.
	DeX DeXConfig `json:"dex,omitempty"`

	// ServiceAccount is the configuration for the service account to create the token.
	ServiceAccount ServiceAccount `json:"serviceAccount,omitempty"`

	// RefreshBefore is the duration before the token expires that the token should be refreshed.
	// +optional
	// +kubebuilder:default:="10m"
	RefreshBefore metav1.Duration `json:"refreshBefore,omitempty"`

	// SecretKey is the key in the secret containing the token.
	SecretKey string `json:"secretKey,omitempty"`
}

type ServiceAccount struct {
	// Name is the name of the service account.
	Name string `json:"name,omitempty"`

	// Audiences are the intendend audiences of the token.
	Audiences []string `json:"audiences,omitempty"`
}

type DeXConfig struct {
	// Endpoint is the URL of the DeX server.
	Endpoint string `json:"endpoint,omitempty"`

	// ClientID is the ID of the client in the DeX server.
	// +optional
	ClientID string `json:"clientID,omitempty"`

	// ClientSecret is the secret of the client in the DeX server.
	// +optional
	ClientSecret string `json:"clientSecret,omitempty"`

	// ClientSecretRef is a reference to the secret containing the client secret of the DeX server.
	// +optional
	ClientSecretRef SecretRef `json:"clientSecretRef,omitempty"`

	// ConnectorID is the ID of the connector in the DeX server.
	// +optional
	ConnectorID string `json:"connectorID,omitempty"`

	// GrantType is the grant type of the token exchange.
	// +optional
	// +kubebuilder:default:="urn:ietf:params:oauth:grant-type:token-exchange"
	GrantType string `json:"grantType,omitempty"`

	// Scopes is the scopes for the token exchange.
	// +optional
	Scopes []string `json:"scopes,omitempty"`

	// RequestedTokenType is the type of the requested token of the token exchange.
	// +optional
	RequestedTokenType string `json:"requestedTokenType,omitempty"`

	// SubjectTokenType is the type of the subject token used in the token exchange.
	// +optional
	SubjectTokenType string `json:"subjectTokenType,omitempty"`
}

type SecretRef struct {
	Name string `json:"name,omitempty"`
}

// DeXTokenStatus defines the observed state of DeXToken.
type DeXTokenStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// TokenSecretName is the name of the secret containing the token.
	TokenSecretName string `json:"tokenSecretName,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// DeXToken is the Schema for the dextokens API.
type DeXToken struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DeXTokenSpec   `json:"spec,omitempty"`
	Status DeXTokenStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// DeXTokenList contains a list of DeXToken.
type DeXTokenList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []DeXToken `json:"items"`
}

func init() {
	SchemeBuilder.Register(&DeXToken{}, &DeXTokenList{})
}
