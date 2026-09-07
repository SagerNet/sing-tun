package tun

import (
	"math"
	"time"
)

const (
	goWheelTick          = int64(time.Millisecond)
	goWheelLevel0Slots   = 128
	goWheelLevel1Slots   = 64
	goWheelLevel1Ticks   = goWheelLevel0Slots
	goWheelRotationTicks = goWheelLevel1Slots * goWheelLevel1Ticks
)

type goWheelNode struct {
	prev     *goWheelNode
	next     *goWheelNode
	slot     **goWheelNode
	deadline int64
	expire   func(now int64)
}

type goWheel struct {
	level0      [goWheelLevel0Slots]*goWheelNode
	level1      [goWheelLevel1Slots]*goWheelNode
	overflow    *goWheelNode
	currentTick int64
	scheduled   int
}

func (w *goWheel) schedule(node *goWheelNode, deadline int64) {
	if node.slot != nil {
		w.unlink(node)
	} else {
		w.scheduled++
	}
	node.deadline = deadline
	w.file(node)
}

func (w *goWheel) cancel(node *goWheelNode) {
	if node.slot == nil {
		return
	}
	w.unlink(node)
	w.scheduled--
}

func (w *goWheel) file(node *goWheelNode) {
	tick := max((node.deadline+goWheelTick-1)/goWheelTick, w.currentTick+1)
	var slot **goWheelNode
	if tick-w.currentTick < goWheelLevel0Slots {
		slot = &w.level0[tick%goWheelLevel0Slots]
	} else if tick/goWheelLevel1Ticks-w.currentTick/goWheelLevel1Ticks < goWheelLevel1Slots {
		slot = &w.level1[(tick/goWheelLevel1Ticks)%goWheelLevel1Slots]
	} else {
		slot = &w.overflow
	}
	node.prev = nil
	node.next = *slot
	if node.next != nil {
		node.next.prev = node
	}
	*slot = node
	node.slot = slot
}

func (w *goWheel) unlink(node *goWheelNode) {
	if node.prev != nil {
		node.prev.next = node.next
	} else {
		*node.slot = node.next
	}
	if node.next != nil {
		node.next.prev = node.prev
	}
	node.prev = nil
	node.next = nil
	node.slot = nil
}

func (w *goWheel) advance(now int64) {
	targetTick := now / goWheelTick
	for w.currentTick < targetTick {
		if w.scheduled == 0 {
			w.currentTick = targetTick
			return
		}
		w.currentTick++
		if w.currentTick%goWheelLevel1Ticks == 0 {
			if w.currentTick%goWheelRotationTicks == 0 {
				w.refile(&w.overflow)
			}
			w.refile(&w.level1[(w.currentTick/goWheelLevel1Ticks)%goWheelLevel1Slots])
		}
		w.fireSlot(&w.level0[w.currentTick%goWheelLevel0Slots], now)
	}
}

func (w *goWheel) refile(slot **goWheelNode) {
	chain := *slot
	*slot = nil
	for chain != nil {
		node := chain
		chain = chain.next
		node.prev = nil
		node.next = nil
		node.slot = nil
		w.file(node)
	}
}

func (w *goWheel) fireSlot(slot **goWheelNode, now int64) {
	for *slot != nil {
		node := *slot
		w.unlink(node)
		w.scheduled--
		node.expire(now)
	}
}

func (w *goWheel) nextDeadline() (int64, bool) {
	if w.scheduled == 0 {
		return 0, false
	}
	deadline := int64(math.MaxInt64)
	for offset := int64(1); offset < goWheelLevel0Slots; offset++ {
		tick := w.currentTick + offset
		if w.level0[tick%goWheelLevel0Slots] != nil {
			deadline = tick * goWheelTick
			break
		}
	}
	level1Index := w.currentTick / goWheelLevel1Ticks
	for offset := int64(1); offset < goWheelLevel1Slots; offset++ {
		index := level1Index + offset
		if w.level1[index%goWheelLevel1Slots] != nil {
			deadline = min(deadline, index*goWheelLevel1Ticks*goWheelTick)
			break
		}
	}
	if w.overflow != nil {
		rotation := (w.currentTick/goWheelRotationTicks + 1) * goWheelRotationTicks * goWheelTick
		deadline = min(deadline, rotation)
	}
	return deadline, true
}
