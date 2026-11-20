package pac

import (
	"bytes"
	"fmt"

	"github.com/jcmturner/rpc/v2/mstypes"

	"github.com/otuschhoff/gokrb5/v8/pac/internal/ndr"
)

// S4UDelegationInfo implements https://msdn.microsoft.com/en-us/library/cc237944.aspx
type S4UDelegationInfo struct {
	// S4U2proxyTarget names the principal to whom the application can forward the ticket.
	S4U2proxyTarget   mstypes.RPCUnicodeString
	TransitedListSize uint32
	// S4UTransitedServices lists the services through which delegation occurred. Its size is TransitedListSize.
	S4UTransitedServices []mstypes.RPCUnicodeString `ndr:"pointer,conformant"`
}

// Unmarshal bytes into the S4UDelegationInfo struct
func (k *S4UDelegationInfo) Unmarshal(b []byte) error {
	var err error
	dec := ndr.NewDecoder(bytes.NewReader(b))
	err = dec.Decode(k)
	if err != nil {
		err = fmt.Errorf("error unmarshaling S4UDelegationInfo: %w", err)
	}
	return err
}

// ProxyTarget returns the service to which the ticket may be forwarded.
func (k S4UDelegationInfo) ProxyTarget() string {
	return k.S4U2proxyTarget.Value
}

// TransitedServices returns a copy of the services in the delegation path.
func (k S4UDelegationInfo) TransitedServices() []string {
	services := make([]string, len(k.S4UTransitedServices))
	for i := range k.S4UTransitedServices {
		services[i] = k.S4UTransitedServices[i].Value
	}
	return services
}
