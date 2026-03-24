package tunnel

// EventType identifies what happened to a tunnel.
type EventType int

const (
	EventRegistered   EventType = iota
	EventUnregistered
)

// Event is emitted when a tunnel is registered or removed.
type Event struct {
	Type   EventType
	Tunnel *Tunnel
}

// EventBus lets components subscribe to tunnel lifecycle events.
type EventBus struct {
	subs []chan Event
}

func NewEventBus() *EventBus { return &EventBus{} }

func (b *EventBus) Subscribe() <-chan Event {
	ch := make(chan Event, 64)
	b.subs = append(b.subs, ch)
	return ch
}

func (b *EventBus) Publish(e Event) {
	for _, ch := range b.subs {
		select {
		case ch <- e:
		default:
		}
	}
}
