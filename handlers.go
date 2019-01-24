package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"html"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/Sirupsen/logrus"
)

// Print the API Request
func printAPIRequest(request Interceptor) {
	logrus.Debug("Request Intercepted.....")
	logrus.Debug("UUID: ", request.UUID)
	logrus.Debug("Headers: ", request.Headers)
	logrus.Debug("Body: ", request.Body)
	logrus.Debug("EnvID: ", request.EnvID)
	logrus.Debug("API Path: ", request.APIPath)
	logrus.Debug("API Method: ", request.APIMethod)
	logrus.Debug("Request Ended.....")
}

func signMessage(body []byte, key []byte) string {
	// A known secret key
	mac := hmac.New(sha512.New, key)
	mac.Write(body)
	signature := mac.Sum(nil)
	encodedSignature := base64.URLEncoding.EncodeToString(signature)
	return encodedSignature
}

// Index route
func Index(w http.ResponseWriter, r *http.Request) {
	var request Interceptor
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&request)
	if err != nil {
		logrus.Fatal("Error: ", err)
		return
	}
	logrus.Infof("Endpoint Invoked %q", html.EscapeString(r.URL.Path))
	printAPIRequest(request)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
}

// Secret route
func Secret(w http.ResponseWriter, r *http.Request) {
	logrus.Infof("Endpoint Invoked %q", html.EscapeString(r.URL.Path))

	var request Interceptor
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&request)
	if err != nil {
		logrus.Fatal("Error: ", err)
		return
	}

	// mac write the content
	key := []byte("rancher123")
	bodyContent, err := json.Marshal(request)
	if err != nil {
		logrus.Fatal("Error: ", err)
		return
	}

	expectedSignature := signMessage(bodyContent, key)
	logrus.Debugf("Signature generated: %s", expectedSignature)
	existingSignature := r.Header.Get("X-API-Auth-Signature")
	logrus.Debugf("Existing Signature: %v", existingSignature)

	if hmac.Equal([]byte(existingSignature), []byte(expectedSignature)) {
		logrus.Infof("Signature Verified...")
	} else {
		logrus.Fatal("Error: Signature not verified")
		return
	}
	printAPIRequest(request)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	logrus.Infof("Endpoint Ended")
}

// Auth route
func Auth(w http.ResponseWriter, r *http.Request) {
	var request Interceptor
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&request)
	if err != nil {
		logrus.Fatal("Error: ", err)
		return
	}
	logrus.Infof("Endpoint Invoked %q", html.EscapeString(r.URL.Path))
	printAPIRequest(request)

	// Check the account ID
	accountID := request.Headers["X-API-Account-Id"]
	logrus.Infof("Account ID %s", accountID)

	kind := request.Headers["X-API-Account-Kind"]
	logrus.Infof("Account Kind %s", kind)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
}

// ModifyBody route
func ModifyBody(w http.ResponseWriter, r *http.Request) {
	var request Interceptor
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&request)
	if err != nil {
		logrus.Fatal("Error: ", err)
		return
	}
	logrus.Infof("Endpoint Invoked %q", html.EscapeString(r.URL.Path))
	printAPIRequest(request)

	// Modify the request body for the stack creation
	if request.APIPath == "/v2-beta/projects/1a5/stack" {
		stackName := "test-" + strconv.Itoa(rand.Intn(99999))
		logrus.Infof("The new stack name: %s", stackName)
		request.Body["name"] = stackName

		// Modify one of the headers
		s := []string{"bar"}
		request.Headers["foo"] = s
		json.NewEncoder(w).Encode(request)

	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
}

// Destination route
func Destination(w http.ResponseWriter, r *http.Request) {
	logrus.Infof("Destination invoked after interceptors...")

	logrus.Debug("Request Method: ", r.Method)
	logrus.Debug("URL: ", r.URL)

	bodyBuffer, _ := ioutil.ReadAll(r.Body)
	logrus.Debug("Body: ", bodyBuffer)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	logrus.Infof("Destination finished...")
}

// ChainedSecret1 route
func ChainedSecret1(w http.ResponseWriter, r *http.Request) {
	logrus.Infof("Chained Secret 1.. Endpoint Invoked %q", html.EscapeString(r.URL.Path))

	var request Interceptor
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&request)
	if err != nil {
		logrus.Fatal("Error: ", err)
		return
	}
	// mac write the content
	key := []byte("secret1")
	bodyContent, err := json.Marshal(request)
	if err != nil {
		logrus.Fatal("Error: ", err)
		return
	}

	expectedSignature := signMessage(bodyContent, key)
	logrus.Debugf("Signature generated: %s", expectedSignature)
	existingSignature := r.Header.Get("X-API-Auth-Signature")
	if existingSignature == "" {
		printAPIRequest(request)
		logrus.Infof("There is no signature provided for this interceptors")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		logrus.Infof("Endpoint Ended")
		return
	}
	logrus.Debugf("Existing Signature: %v", existingSignature)

	if hmac.Equal([]byte(existingSignature), []byte(expectedSignature)) {
		logrus.Infof("Signature Verified...")
	} else {
		logrus.Fatal("Error: Signature not verified")
		return
	}
	printAPIRequest(request)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	logrus.Infof("Endpoint Ended")
}

// ChainedSecret2 route
func ChainedSecret2(w http.ResponseWriter, r *http.Request) {
	logrus.Infof("Chained Secret 2.. Endpoint Invoked %q", html.EscapeString(r.URL.Path))

	var request Interceptor
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&request)
	if err != nil {
		logrus.Fatal("Error: ", err)
		return
	}
	// mac write the content
	key := []byte("secret2")
	bodyContent, err := json.Marshal(request)
	if err != nil {
		logrus.Fatal("Error: ", err)
		return
	}

	expectedSignature := signMessage(bodyContent, key)
	logrus.Debugf("Signature generated: %s", expectedSignature)
	existingSignature := r.Header.Get("X-API-Auth-Signature")
	if existingSignature == "" {
		printAPIRequest(request)
		logrus.Infof("There is no signature provided for this interceptors")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		logrus.Infof("Endpoint Ended")
		return
	}
	logrus.Debugf("Existing Signature: %v", existingSignature)

	if hmac.Equal([]byte(existingSignature), []byte(expectedSignature)) {
		logrus.Infof("Signature Verified...")
	} else {
		logrus.Fatal("Error: Signature not verified")
		return
	}
	printAPIRequest(request)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	logrus.Infof("Endpoint Ended")
}

// BlockLDAPUser route
func BlockLDAPUser(w http.ResponseWriter, r *http.Request) {
	var request Interceptor
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&request)
	if err != nil {
		logrus.Fatal("Error: ", err)
		return
	}
	logrus.Infof("Endpoint Invoked %q", html.EscapeString(r.URL.Path))
	printAPIRequest(request)

	// Get account id
	accountIDEnv := os.Getenv("LDAP_BLOCK_ACCOUNT_ID")
	// Check the account ID
	accountID := request.Headers["X-API-Account-Id"]
	logrus.Infof("Account ID %s", accountID)
	if accountID[0] == accountIDEnv {
		w.WriteHeader(401)
		logrus.Info("This user is not authorized..")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
}

// Unhandled route
func Unhandled(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(500)
}

// Sleepy route
func Sleepy(w http.ResponseWriter, r *http.Request) {
	logrus.Infof("Sleeping for 10 minutes")
	time.Sleep(time.Second * 600)
	var request Interceptor
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&request)
	if err != nil {
		logrus.Fatal("Error: ", err)
		return
	}
	logrus.Infof("Endpoint Invoked %q", html.EscapeString(r.URL.Path))
	printAPIRequest(request)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
}

// Failure route
func Failure(w http.ResponseWriter, r *http.Request) {
	var request Interceptor
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&request)
	if err != nil {
		logrus.Fatal("Error: ", err)
		return
	}
	logrus.Infof("Endpoint Invoked %q", html.EscapeString(r.URL.Path))
	printAPIRequest(request)

	request.Message = "This is a custom error"

	logrus.Infof("Returning 429 error")
	w.WriteHeader(429)
	json.NewEncoder(w).Encode(request)
}
