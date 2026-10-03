package cloud

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func (s *Server) createCheckout(w http.ResponseWriter, r *http.Request) {
	if !s.csrfValid(r) {
		http.Error(w, "invalid origin", http.StatusForbidden)
		return
	}
	if !s.config.BillingEnabled() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "billing is not configured"})
		return
	}
	user := userFromContext(r.Context())
	form := url.Values{"mode": {"subscription"}, "line_items[0][price]": {s.config.StripeTeamPriceID}, "line_items[0][quantity]": {"1"}, "success_url": {s.config.BaseURL + "/app?billing=success"}, "cancel_url": {s.config.BaseURL + "/app?billing=cancelled"}, "client_reference_id": {strconv.FormatInt(user.ID, 10)}, "metadata[user_id]": {strconv.FormatInt(user.ID, 10)}}
	if user.StripeCustomerID != "" {
		form.Set("customer", user.StripeCustomerID)
	} else if user.Email != "" {
		form.Set("customer_email", user.Email)
	}
	var response struct {
		URL string `json:"url"`
	}
	if err := s.stripeRequest(r, http.MethodPost, "/v1/checkout/sessions", form, &response); err != nil {
		s.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) createPortal(w http.ResponseWriter, r *http.Request) {
	if !s.csrfValid(r) {
		http.Error(w, "invalid origin", http.StatusForbidden)
		return
	}
	user := userFromContext(r.Context())
	if !s.config.BillingEnabled() || user.StripeCustomerID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no billing account"})
		return
	}
	form := url.Values{"customer": {user.StripeCustomerID}, "return_url": {s.config.BaseURL + "/app"}}
	var response struct {
		URL string `json:"url"`
	}
	if err := s.stripeRequest(r, http.MethodPost, "/v1/billing_portal/sessions", form, &response); err != nil {
		s.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) stripeRequest(r *http.Request, method, path string, form url.Values, destination any) error {
	request, err := http.NewRequestWithContext(r.Context(), method, strings.TrimRight(s.config.StripeAPIBase, "/")+path, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	request.SetBasicAuth(s.config.StripeSecretKey, "")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := s.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("stripe API returned %s: %s", response.Status, string(body))
	}
	return json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(destination)
}

func (s *Server) stripeWebhook(w http.ResponseWriter, r *http.Request) {
	if s.config.StripeWebhookSecret == "" {
		http.Error(w, "billing is not configured", http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if !verifyStripeSignature(body, r.Header.Get("Stripe-Signature"), s.config.StripeWebhookSecret, time.Now()) {
		http.Error(w, "invalid signature", http.StatusBadRequest)
		return
	}
	var event struct {
		Type string `json:"type"`
		Data struct {
			Object struct {
				Customer          string `json:"customer"`
				ClientReferenceID string `json:"client_reference_id"`
				Status            string `json:"status"`
			} `json:"object"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &event) != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	switch event.Type {
	case "checkout.session.completed":
		id, _ := strconv.ParseInt(event.Data.Object.ClientReferenceID, 10, 64)
		if id > 0 {
			_ = s.store.SetBilling(ctx, id, "team", event.Data.Object.Customer)
		}
	case "customer.subscription.updated":
		user, err := s.store.UserByStripeCustomer(ctx, event.Data.Object.Customer)
		if err == nil {
			plan := "free"
			if event.Data.Object.Status == "active" || event.Data.Object.Status == "trialing" {
				plan = "team"
			}
			_ = s.store.SetBilling(ctx, user.ID, plan, event.Data.Object.Customer)
		}
	case "customer.subscription.deleted":
		user, err := s.store.UserByStripeCustomer(ctx, event.Data.Object.Customer)
		if err == nil {
			_ = s.store.SetBilling(ctx, user.ID, "free", event.Data.Object.Customer)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func verifyStripeSignature(body []byte, header, secret string, now time.Time) bool {
	var timestamp int64
	var signatures []string
	for _, field := range strings.Split(header, ",") {
		parts := strings.SplitN(strings.TrimSpace(field), "=", 2)
		if len(parts) != 2 {
			continue
		}
		if parts[0] == "t" {
			timestamp, _ = strconv.ParseInt(parts[1], 10, 64)
		} else if parts[0] == "v1" {
			signatures = append(signatures, parts[1])
		}
	}
	if timestamp == 0 || now.Sub(time.Unix(timestamp, 0)) > 5*time.Minute || time.Unix(timestamp, 0).Sub(now) > 5*time.Minute {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d.", timestamp)
	mac.Write(body)
	expected := mac.Sum(nil)
	for _, signature := range signatures {
		provided, err := hex.DecodeString(signature)
		if err == nil && hmac.Equal(expected, provided) {
			return true
		}
	}
	return false
}
