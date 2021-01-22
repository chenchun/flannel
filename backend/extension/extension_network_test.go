package extension

import (
	"context"
	"net/http"
	_ "net/http/pprof"
	"sync"
	"testing"
	"time"

	"github.com/coreos/flannel/pkg/ip"
	"github.com/coreos/flannel/subnet"
)

var _ subnet.Manager = &fakeSubnetManager{}

type fakeSubnetManager struct {
	events chan subnet.Event
}

func (f *fakeSubnetManager) GetNetworkConfig(ctx context.Context) (*subnet.Config, error) {
	panic("implement me")
}

func (f *fakeSubnetManager) AcquireLease(ctx context.Context, attrs *subnet.LeaseAttrs) (*subnet.Lease, error) {
	panic("implement me")
}

func (f *fakeSubnetManager) RenewLease(ctx context.Context, lease *subnet.Lease) error {
	panic("implement me")
}

func (f *fakeSubnetManager) WatchLease(ctx context.Context, sn ip.IP4Net, cursor interface{}) (subnet.LeaseWatchResult, error) {
	panic("implement me")
}

func (f *fakeSubnetManager) WatchLeases(ctx context.Context, cursor interface{}) (subnet.LeaseWatchResult, error) {
	select {
	case event := <-f.events:
		return subnet.LeaseWatchResult{
			Events: []subnet.Event{event},
		}, nil
	case <-ctx.Done():
		return subnet.LeaseWatchResult{}, context.Canceled
	}
}

func (f *fakeSubnetManager) Name() string {
	panic("implement me")
}

func TestRun(t *testing.T) {
	go func() {
		http.ListenAndServe("0.0.0.0:6060", nil)
	}()
	f := &fakeSubnetManager{events: make(chan subnet.Event)}
	network := network{
		lease: nil,
		sm:    f,
	}
	ctx, cancel := context.WithCancel(context.TODO())
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		network.Run(ctx)
	}()
	time.Sleep(time.Second)
	f.events <- subnet.Event{}
	cancel()
	wg.Wait()
}
