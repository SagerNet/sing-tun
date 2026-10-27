package tun

import (
	"net/netip"

	"go4.org/netipx"
)

// planFamily chooses the smaller route installation for one address family.
//
// Punching exclude prefixes out of a wide capture prefix turns each hole into
// many complement prefixes, and every one of those becomes a kernel route.
// The other representation keeps the original capture prefixes pointed at the
// tun and adds the excluded prefixes pointed at the existing default gateway.
// Longest-prefix match makes the two equivalent. The smaller one is used.
func planFamily(capture, exclude []netip.Prefix) (toTun []netip.Prefix, toGateway []netip.Prefix, err error) {
	if len(capture) == 0 {
		return nil, nil, nil
	}
	if len(exclude) == 0 {
		return append([]netip.Prefix(nil), capture...), nil, nil
	}
	captureSet, err := prefixSet(capture)
	if err != nil {
		return nil, nil, err
	}
	excludeSet, err := prefixSet(exclude)
	if err != nil {
		return nil, nil, err
	}
	complement, err := subtractSet(captureSet, excludeSet)
	if err != nil {
		return nil, nil, err
	}
	var kept []netip.Prefix
	for _, prefix := range captureSet.Prefixes() {
		if excludeSet.ContainsPrefix(prefix) {
			continue
		}
		kept = append(kept, prefix)
	}
	var gateway []netip.Prefix
	if len(kept) > 0 {
		keptSet, keptErr := prefixSet(kept)
		if keptErr != nil {
			return nil, nil, keptErr
		}
		overlap, overlapErr := intersectSets(excludeSet, captureSet)
		if overlapErr != nil {
			return nil, nil, overlapErr
		}
		gatewaySet, gatewayErr := intersectSets(overlap, keptSet)
		if gatewayErr != nil {
			return nil, nil, gatewayErr
		}
		gateway = gatewaySet.Prefixes()
	}
	if len(complement) <= len(kept)+len(gateway) {
		return complement, nil, nil
	}
	return kept, gateway, nil
}

func prefixSet(prefixes []netip.Prefix) (*netipx.IPSet, error) {
	var builder netipx.IPSetBuilder
	for _, prefix := range prefixes {
		builder.AddPrefix(prefix)
	}
	return builder.IPSet()
}

func subtractPrefixes(capture, exclude []netip.Prefix) ([]netip.Prefix, error) {
	captureSet, err := prefixSet(capture)
	if err != nil {
		return nil, err
	}
	excludeSet, err := prefixSet(exclude)
	if err != nil {
		return nil, err
	}
	return subtractSet(captureSet, excludeSet)
}

func subtractSet(capture, exclude *netipx.IPSet) ([]netip.Prefix, error) {
	var builder netipx.IPSetBuilder
	if capture != nil {
		builder.AddSet(capture)
	}
	if exclude != nil {
		builder.RemoveSet(exclude)
	}
	result, err := builder.IPSet()
	if err != nil {
		return nil, err
	}
	return result.Prefixes(), nil
}

func ipv4Mask(bits int) [4]byte {
	raw := maskBytes(bits, 32)
	var out [4]byte
	copy(out[:], raw[:4])
	return out
}

func ipv6Mask(bits int) [16]byte {
	return maskBytes(bits, 128)
}

func maskBytes(bits, size int) [16]byte {
	if bits < 0 {
		bits = 0
	}
	if bits > size {
		bits = size
	}
	var out [16]byte
	for i := 0; i < bits/8; i++ {
		out[i] = 0xff
	}
	if rem := bits % 8; rem != 0 {
		out[bits/8] = ^byte(0xff >> rem)
	}
	return out
}

func intersectSets(left, right *netipx.IPSet) (*netipx.IPSet, error) {
	var builder netipx.IPSetBuilder
	if left != nil {
		builder.AddSet(left)
	}
	if right != nil {
		builder.Intersect(right)
	}
	return builder.IPSet()
}
