package config_test

import (
	"errors"
	"fmt"

	"github.com/otuschhoff/gokrb5/v8/config"
)

func ExampleNewFromString() {
	const input = `[realms]
EXAMPLE.COM = {
	kdc = kdc.example.com
	v4_instance_convert = {
		legacy = ignored
	}
}
[libdefaults]
	default_realm = EXAMPLE.COM
`

	cfg, err := config.NewFromString(input)
	warning, isWarning := errors.AsType[config.UnsupportedDirective](err)
	isFatal := err != nil && !isWarning
	if cfg == nil || isFatal {
		fmt.Println("Cannot load config:", err)
		return
	}

	if isWarning {
		fmt.Println("Warning:", warning)
	}

	fmt.Println("Default realm:", cfg.LibDefaults.DefaultRealm)

	// Output:
	// Warning: v4 configurations are not supported
	// Default realm: EXAMPLE.COM
}
