package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"unsafe"

	"github.com/opentdf/platform/sdk"
)

var SdkInstance *sdk.SDK

// Global config store
var (
	configStore          = map[uintptr]*sdk.ConfigWrapper{}
	clientCredentialsMap = map[uintptr]struct {
		ClientID     string
		ClientSecret string
	}{}
	currentConfigID uintptr = 1
)

//export CreateConfig
func CreateConfig() uintptr {
	config := sdk.NewConfigWrapper()
	configID := currentConfigID
	configStore[configID] = config
	currentConfigID++
	return configID
}

//export SetClientCredentials
func SetClientCredentials(configID uintptr, clientID *C.char, clientSecret *C.char) *C.char {
	if clientID == nil || clientSecret == nil {
		return C.CString("Client ID and Client Secret are required")
	}

	_, ok := configStore[configID]
	if !ok {
		return C.CString("Invalid config ID")
	}

	clientCredentialsMap[configID] = struct {
		ClientID     string
		ClientSecret string
	}{
		ClientID:     C.GoString(clientID),
		ClientSecret: C.GoString(clientSecret),
	}

	return nil
}

//export SetInsecureSkipVerify
func SetInsecureSkipVerify(configID uintptr) *C.char {
	config, ok := configStore[configID]
	if !ok {
		return C.CString("Invalid config ID")
	}

	option := sdk.WithInsecureSkipVerifyConn()
	if option == nil {
		return C.CString("Failed to apply insecure skip verify option")
	}

	option(config.InternalConfig())
	return nil
}

//export InitializeSdk
func InitializeSdk(configID uintptr, platformEndpoint *C.char, errMessage **C.char) uintptr {
	// Convert C string to Go string
	goEndpoint := C.GoString(platformEndpoint)

	var opts []sdk.Option

	if creds, exists := clientCredentialsMap[configID]; exists {
		opts = append(opts, sdk.WithClientCredentials(creds.ClientID, creds.ClientSecret, []string{}))
	}

	var err error
	sdkInstance, err := sdk.New(goEndpoint, opts...)
	if err != nil {
		// Set the error message and return nil pointer
		*errMessage = C.CString(fmt.Sprintf("Error initializing SDK: %s", err.Error()))
		return 0
	}

	// Return a success message
	return uintptr(unsafe.Pointer(sdkInstance))
}
