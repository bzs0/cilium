// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package sock

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"

	"github.com/cilium/cilium/pkg/hubble/parser/common"

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/wrapperspb"

	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/hubble/parser/errors"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/monitor"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

// Parser is a parser for SockTraceNotify payloads
type Parser struct {
	log            logrus.FieldLogger
	endpointGetter getters.EndpointGetter
	identityGetter getters.IdentityGetter
	dnsGetter      getters.DNSGetter
	ipGetter       getters.IPGetter
	serviceGetter  getters.ServiceGetter
	epResolver     *common.EndpointResolver
}

// New creates a new parser
func New(log logrus.FieldLogger,
	endpointGetter getters.EndpointGetter,
	identityGetter getters.IdentityGetter,
	dnsGetter getters.DNSGetter,
	ipGetter getters.IPGetter,
	serviceGetter getters.ServiceGetter,
) (*Parser, error) {
	return &Parser{
		log:            log,
		endpointGetter: endpointGetter,
		identityGetter: identityGetter,
		dnsGetter:      dnsGetter,
		ipGetter:       ipGetter,
		serviceGetter:  serviceGetter,
		epResolver:     common.NewEndpointResolver(log, endpointGetter, identityGetter, ipGetter),
	}, nil
}

// Decode takes a raw trace sock event payload obtained from the perf event ring
// buffer and decodes it into a flow
func (p *Parser) Decode(data []byte, decoded *pb.Flow) error {
	if len(data) == 0 {
		return errors.ErrEmptyData
	}

	eventType := data[0]
	if eventType != monitorAPI.MessageTypeTraceSock {
		return errors.NewErrInvalidType(eventType)
	}

	sock := &monitor.SockTraceNotify{}
	if err := binary.Read(bytes.NewReader(data), byteorder.Native, sock); err != nil {
		return fmt.Errorf("failed to parse sock trace event: %w", err)
	}

	isRevNat := decodeRevNat(sock.XlatePoint)

	var srcIP, dstIP net.IP
	var srcPort, dstPort uint16
	var ipVersion pb.IPVersion

	dstIP, ipVersion = decodeDstIP(sock)
	dstPort = byteorder.NetworkToHost16(sock.DstPort)

	if isRevNat.GetValue() {
		srcIP, dstIP = dstIP, srcIP
		srcPort, dstPort = dstPort, srcPort
	}

	decoded.Verdict = pb.Verdict_FORWARDED // TODO: Introduce new verdict?
	decoded.IP = decodeL3(srcIP, dstIP, ipVersion)
	decoded.L4 = decodeL4(sock.L4Proto, srcPort, dstPort)
	decoded.Source = p.epResolver.ResolveEndpoint(dstIP, 0)
	decoded.SourceNames = nil // TODO: This requires the destination endpoint ID
	decoded.SourceService = p.decodeService(srcIP, srcPort)
	decoded.Destination = p.epResolver.ResolveEndpoint(dstIP, 0)
	decoded.DestinationNames = nil // TODO: This requires the source endpoint ID
	decoded.DestinationService = p.decodeService(dstIP, dstPort)
	decoded.Type = pb.FlowType_SOCK
	decoded.EventType = decodeCiliumEventType(sock.Type, sock.XlatePoint)
	decoded.SockXlatePoint = pb.SocketTranslationPoint(sock.XlatePoint + 1)
	decoded.IsReply = isRevNat
	return nil
}

func decodeDstIP(sock *monitor.SockTraceNotify) (addr net.IP, ipVersion pb.IPVersion) {
	// TODO: We want to have a flag for this in monitorAPI
	isIPv6 := (sock.Flags & 0x80) != 0

	if isIPv6 {
		return sock.DstIP.IP(), pb.IPVersion_IPv6
	} else if dstIP, ok := netip.AddrFromSlice(sock.DstIP[:4]); ok {
		return dstIP.AsSlice(), pb.IPVersion_IPv4
	}

	return nil, pb.IPVersion_IP_NOT_USED
}

func decodeL3(srcIP, dstIP net.IP, ipVersion pb.IPVersion) *pb.IP {
	var srcIPStr, dstIPStr string
	if srcIP != nil {
		srcIPStr = srcIP.String()
	}
	if dstIP != nil {
		dstIPStr = dstIP.String()
	}

	return &pb.IP{
		Source:      srcIPStr,
		Destination: dstIPStr,
		IpVersion:   ipVersion,
	}
}

func decodeL4(proto uint8, srcPort, dstPort uint16) *pb.Layer4 {
	switch proto {
	case monitor.L4ProtocolTCP:
		return &pb.Layer4{
			Protocol: &pb.Layer4_TCP{
				TCP: &pb.TCP{
					SourcePort:      uint32(srcPort),
					DestinationPort: uint32(dstPort),
				},
			},
		}
	case monitor.L4ProtocolUDP:
		return &pb.Layer4{
			Protocol: &pb.Layer4_UDP{
				UDP: &pb.UDP{
					SourcePort:      uint32(srcPort),
					DestinationPort: uint32(dstPort),
				},
			},
		}
	}

	return nil
}

func (p *Parser) decodeService(ip net.IP, port uint16) *pb.Service {
	if p.serviceGetter != nil {
		return p.serviceGetter.GetServiceByAddr(ip, port)
	}

	return nil
}

func decodeCiliumEventType(eventType, subtype uint8) *pb.CiliumEventType {
	return &pb.CiliumEventType{
		Type:    int32(eventType),
		SubType: int32(subtype),
	}
}

func isPostXlate(xlatePoint uint8) bool {
	switch xlatePoint {
	case monitor.XlatePointPostDirectionRev,
		monitor.XlatePointPostDirectionFwd:
		return true
	}

	return false
}

func decodeRevNat(xlatePoint uint8) *wrapperspb.BoolValue {
	switch xlatePoint {
	case monitor.XlatePointPreDirectionFwd,
		monitor.XlatePointPostDirectionFwd:
		return &wrapperspb.BoolValue{Value: false}
	case monitor.XlatePointPreDirectionRev,
		monitor.XlatePointPostDirectionRev:
		return &wrapperspb.BoolValue{Value: true}
	}

	return nil
}
