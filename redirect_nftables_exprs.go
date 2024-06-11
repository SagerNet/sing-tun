//go:build linux

package tun

import (
	"net/netip"
	"unsafe"

	"github.com/sagernet/nftables"
	"github.com/sagernet/nftables/expr"

	"go4.org/netipx"
)

func nftablesIfname(n string) []byte {
	b := make([]byte, 16)
	copy(b, n+"\x00")
	return b
}

func nftablesCreateExcludeDestinationIPSet(
	nft *nftables.Conn, table *nftables.Table, chain *nftables.Chain,
	id uint32, name string, family nftables.TableFamily, invert bool,
) {
	exprs := []expr.Any{
		&expr.Meta{
			Key:      expr.MetaKeyNFPROTO,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{byte(family)},
		},
	}
	if family == nftables.TableFamilyIPv4 {
		exprs = append(exprs,
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				DestRegister:  1,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        16,
				Len:           4,
			},
		)
	} else {
		exprs = append(exprs,
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				DestRegister:  1,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        24,
				Len:           16,
			},
		)
	}
	exprs = append(exprs,
		&expr.Lookup{
			SourceRegister: 1,
			SetID:          id,
			SetName:        name,
			Invert:         invert,
		},
		&expr.Counter{},
		&expr.Verdict{
			Kind: expr.VerdictReturn,
		})
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: exprs,
	})
}

func nftablesCreateIPSet(
	nft *nftables.Conn, table *nftables.Table,
	id uint32, name string, family nftables.TableFamily,
	setList []*netipx.IPSet, prefixList []netip.Prefix, appendDefault bool, update bool,
) (*nftables.Set, error) {
	if len(prefixList) > 0 {
		var builder netipx.IPSetBuilder
		if appendDefault && len(setList) == 0 {
			if family == nftables.TableFamilyIPv4 {
				prefixList = append(prefixList, netip.PrefixFrom(netip.IPv4Unspecified(), 0))
			} else {
				prefixList = append(prefixList, netip.PrefixFrom(netip.IPv6Unspecified(), 0))
			}
		}
		for _, prefix := range prefixList {
			builder.AddPrefix(prefix)
		}

		ipSet, err := builder.IPSet()
		if err != nil {
			return nil, err
		}
		setList = append(setList, ipSet)
	}
	ipSets := make([]*myIPSet, 0, len(setList))
	var rangeLen int
	for _, set := range setList {
		mySet := (*myIPSet)(unsafe.Pointer(set))
		ipSets = append(ipSets, mySet)
		rangeLen += len(mySet.rr)
	}
	setElements := make([]nftables.SetElement, 0, len(prefixList)+rangeLen)
	for _, mySet := range ipSets {
		for _, rr := range mySet.rr {
			if (family == nftables.TableFamilyIPv4) != rr.from.Is4() {
				continue
			}
			endAddr := rr.to.Next()
			if !endAddr.IsValid() {
				endAddr = rr.from
			}
			setElements = append(setElements, nftables.SetElement{
				Key: rr.from.AsSlice(),
			})
			setElements = append(setElements, nftables.SetElement{
				Key:         endAddr.AsSlice(),
				IntervalEnd: true,
			})
		}
	}
	var keyType nftables.SetDatatype
	if family == nftables.TableFamilyIPv4 {
		keyType = nftables.TypeIPAddr
	} else {
		keyType = nftables.TypeIP6Addr
	}
	mySet := &nftables.Set{
		Table:    table,
		ID:       id,
		Name:     name,
		Interval: true,
		KeyType:  keyType,
	}
	if id == 0 {
		mySet.Anonymous = true
		mySet.Constant = true
	}
	if id == 0 {
		err := nft.AddSet(mySet, setElements)
		if err != nil {
			return nil, err
		}
		return mySet, nil
	} else if update {
		nft.FlushSet(mySet)
	} else {
		err := nft.AddSet(mySet, nil)
		if err != nil {
			return nil, err
		}
	}
	for len(setElements) > 0 {
		toAdd := setElements
		if len(toAdd) > 1000 {
			toAdd = toAdd[:1000]
		}
		setElements = setElements[len(toAdd):]
		err := nft.SetAddElements(mySet, toAdd)
		if err != nil {
			return nil, err
		}
		err = nft.Flush()
		if err != nil {
			return nil, err
		}
	}
	return mySet, nil
}

type myIPSet struct {
	rr []myIPRange
}

type myIPRange struct {
	from netip.Addr
	to   netip.Addr
}
