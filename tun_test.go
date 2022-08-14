package tun

import (
	"reflect"
	"testing"

	"github.com/sagernet/sing/common/ranges"
)

func TestUIDRanges(t *testing.T) {
	for _, testRange := range []struct {
		include     []ranges.Range[uint32]
		exclude     []ranges.Range[uint32]
		androidUser []int
		expected    []ranges.Range[uint32]
	}{
		{},
		{
			include: []ranges.Range[uint32]{
				ranges.NewSingle[uint32](0),
				ranges.NewSingle[uint32](1000),
			},
			expected: []ranges.Range[uint32]{
				{Start: 1, End: 999},
				{Start: 1001, End: userEnd},
			},
		},
		{
			androidUser: []int{0},
			expected: []ranges.Range[uint32]{
				{Start: androidUserRange, End: userEnd},
			},
		},
		{
			androidUser: []int{0},
			expected: []ranges.Range[uint32]{
				{Start: 100000, End: userEnd},
			},
		},
		{
			androidUser: []int{10},
			include: []ranges.Range[uint32]{
				ranges.NewSingle[uint32](0),
			},
			expected: []ranges.Range[uint32]{
				{Start: 1, End: androidUserRange*10 - 1},
				{Start: androidUserRange * 11, End: userEnd},
			},
		},
		{
			include: []ranges.Range[uint32]{
				{Start: 123456, End: 123456},
			},
			exclude: []ranges.Range[uint32]{
				{Start: 1000, End: 1000},
			},
			androidUser: []int{0},
			expected: []ranges.Range[uint32]{
				{Start: 1000, End: 1000},
				{Start: 100000, End: 123455},
				{Start: 123457, End: userEnd},
			},
		},
	} {
		result := buildExcludedRanges(testRange.include, testRange.exclude, testRange.androidUser)
		if !reflect.DeepEqual(result, testRange.expected) {
			t.Fatal("input", testRange.include, testRange.exclude, testRange.androidUser, "\nexpected", testRange.expected, "\ngot", result)
		}
	}
}
