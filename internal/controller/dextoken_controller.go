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

package controller

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	dexchangev1alpha1 "github.com/miscord-dev/dexchange/api/v1alpha1"
	"github.com/miscord-dev/dexchange/internal/dex"
	authenticationv1 "k8s.io/api/authentication/v1"
)

// DeXTokenReconciler reconciles a DeXToken object
type DeXTokenReconciler struct {
	client.Client
	HTTPClient *http.Client
	Scheme     *runtime.Scheme
}

// +kubebuilder:rbac:groups=dexchange.miscord.win,resources=dextokens,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=dexchange.miscord.win,resources=dextokens/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=dexchange.miscord.win,resources=dextokens/finalizers,verbs=update
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=serviceaccounts,verbs=get;list;watch
// +kubebuilder:rbac:groups=core,resources=serviceaccounts/token,verbs=create

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the DeXToken object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/reconcile
func (r *DeXTokenReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	dexToken := &dexchangev1alpha1.DeXToken{}
	if err := r.Client.Get(ctx, req.NamespacedName, dexToken); err != nil {
		return ctrl.Result{}, err
	}

	if !dexToken.ObjectMeta.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	defer func() {
		if err := r.Client.Status().Update(ctx, dexToken); err != nil {
			logger.Error(err, "failed to update DeXToken status")
		}
	}()

	if dexToken.Status.TokenSecretName == "" {
		dexToken.Status.TokenSecretName = dexToken.Name

		return ctrl.Result{
			Requeue: true,
		}, nil
	}

	return r.reconcileNormal(ctx, dexToken)
}

func (r *DeXTokenReconciler) reconcileNormal(ctx context.Context, dexToken *dexchangev1alpha1.DeXToken) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	secretKey := dexToken.Spec.SecretKey

	var secret corev1.Secret
	if err := r.Client.Get(ctx, client.ObjectKey{
		Namespace: dexToken.Namespace,
		Name:      dexToken.Status.TokenSecretName,
	}, &secret); err != nil && !apierrors.IsNotFound(err) {
		return ctrl.Result{}, err
	}

	if res, err := r.checkExpired(ctx, dexToken, &secret, secretKey); err != nil || res != (ctrl.Result{}) {
		return res, err
	}

	token, err := r.issueToken(ctx, dexToken)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to issue token: %w", err)
	}
	logger.Info("new token is issued")

	secret.Namespace = dexToken.Namespace
	secret.Name = dexToken.Status.TokenSecretName

	_, err = ctrl.CreateOrUpdate(ctx, r.Client, &secret, func() error {
		secret.Data = make(map[string][]byte, 1)
		secret.Data[secretKey] = []byte(token)

		return ctrl.SetControllerReference(dexToken, &secret, r.Scheme)
	})
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to create or update secret: %w", err)
	}

	if res, err := r.checkExpired(ctx, dexToken, &secret, secretKey); err != nil || res != (ctrl.Result{}) {
		return res, err
	}

	return ctrl.Result{
		RequeueAfter: dexToken.Spec.RefreshBefore.Duration,
	}, nil
}

func (r *DeXTokenReconciler) checkExpired(ctx context.Context, dexToken *dexchangev1alpha1.DeXToken, secret *corev1.Secret, secretKey string) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	now := time.Now()
	exp, err := dex.GetTokenExp(string(secret.Data[secretKey]))
	if err == nil {
		refreshedAt := exp.Add(-dexToken.Spec.RefreshBefore.Duration)
		if refreshedAt.After(now) {
			return ctrl.Result{
				RequeueAfter: refreshedAt.Sub(now),
			}, nil
		}
	} else {
		logger.Info("failed to get token expiration", "error", err)
	}

	return ctrl.Result{}, nil
}

func (r *DeXTokenReconciler) issueToken(ctx context.Context, dexToken *dexchangev1alpha1.DeXToken) (string, error) {
	values := url.Values{}
	dexSpec := dexToken.Spec.DeX

	if dexSpec.ConnectorID != "" {
		values.Add("connector_id", dexSpec.ConnectorID)
	}
	if dexSpec.GrantType != "" {
		values.Add("grant_type", dexSpec.GrantType)
	} else {
		values.Add("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	}
	if dexSpec.RequestedTokenType != "" {
		values.Add("requested_token_type", dexSpec.RequestedTokenType)
	}
	if dexSpec.SubjectTokenType != "" {
		values.Add("subject_token_type", dexSpec.SubjectTokenType)
	}
	if len(dexSpec.Scopes) > 0 {
		values.Add("scope", strings.Join(dexSpec.Scopes, " "))
	} else {
		values.Add("scope", "openid")
	}

	saToken, err := r.issueServiceAccountToken(ctx, dexToken)
	if err != nil {
		return "", fmt.Errorf("failed to issue token: %w", err)
	}
	values.Add("subject_token", saToken)

	clientSecret, err := r.getClientSecret(ctx, dexToken)
	if err != nil {
		return "", fmt.Errorf("failed to get client secret: %w", err)
	}

	config := dex.Config{
		Client:    r.HTTPClient,
		Endpoint:  dexToken.Spec.DeX.Endpoint,
		Values:    values,
		BasicAuth: fmt.Sprintf("%s:%s", dexToken.Spec.DeX.ClientID, clientSecret),
	}

	token, err := dex.Issue(ctx, config)
	if err != nil {
		return "", fmt.Errorf("failed to issue token: %w", err)
	}

	return token, nil
}

func (r *DeXTokenReconciler) issueServiceAccountToken(ctx context.Context, dexToken *dexchangev1alpha1.DeXToken) (string, error) {
	serviceAccountName := dexToken.Spec.ServiceAccount.Name

	var serviceAccount corev1.ServiceAccount
	err := r.Client.Get(ctx, client.ObjectKey{
		Namespace: dexToken.Namespace,
		Name:      serviceAccountName,
	}, &serviceAccount)
	if err != nil {
		return "", fmt.Errorf("failed to get ServiceAccount %s: %w", serviceAccountName, err)
	}

	token := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences:         dexToken.Spec.ServiceAccount.Audiences,
			ExpirationSeconds: ptr.To[int64](600),
		},
	}

	err = r.Client.SubResource("token").Create(ctx, &serviceAccount, token, &client.SubResourceCreateOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to create token for ServiceAccount %s: %w", serviceAccountName, err)
	}

	return token.Status.Token, nil
}

func (r *DeXTokenReconciler) getClientSecret(ctx context.Context, dexToken *dexchangev1alpha1.DeXToken) (string, error) {
	if dexToken.Spec.DeX.ClientSecretRef.Name != "" {
		var secret corev1.Secret
		if err := r.Client.Get(ctx, client.ObjectKey{
			Namespace: dexToken.Namespace,
			Name:      dexToken.Spec.DeX.ClientSecretRef.Name,
		}, &secret); err != nil {
			return "", err
		}

		return string(secret.Data["clientSecret"]), nil
	}

	return dexToken.Spec.DeX.ClientSecret, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *DeXTokenReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&dexchangev1alpha1.DeXToken{}).
		Named("dextoken").
		Owns(&corev1.Secret{}).
		Complete(r)
}
