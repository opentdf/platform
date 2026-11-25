package authorization

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	attrs "github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	otdfSDK "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/sdk/sdkconnect"
	"github.com/opentdf/platform/service/internal/access/v2"
	"github.com/opentdf/platform/service/pkg/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type warmupPolicyClient struct {
	sdkconnect.AttributesServiceClient
	sdkconnect.SubjectMappingServiceClient
	sdkconnect.RegisteredResourcesServiceClient
	sdkconnect.ObligationsServiceClient
	beforeAttributes func(context.Context) error
	attributeCalls   atomic.Int32
}

func (c *warmupPolicyClient) ListAttributes(ctx context.Context, _ *attrs.ListAttributesRequest) (*attrs.ListAttributesResponse, error) {
	c.attributeCalls.Add(1)
	if err := c.beforeAttributes(ctx); err != nil {
		return nil, err
	}
	return &attrs.ListAttributesResponse{}, nil
}

func (*warmupPolicyClient) ListSubjectMappings(context.Context, *subjectmapping.ListSubjectMappingsRequest) (*subjectmapping.ListSubjectMappingsResponse, error) {
	return &subjectmapping.ListSubjectMappingsResponse{}, nil
}

func (*warmupPolicyClient) ListRegisteredResources(context.Context, *registeredresources.ListRegisteredResourcesRequest) (*registeredresources.ListRegisteredResourcesResponse, error) {
	return &registeredresources.ListRegisteredResourcesResponse{}, nil
}

func (*warmupPolicyClient) ListObligations(context.Context, *obligations.ListObligationsRequest) (*obligations.ListObligationsResponse, error) {
	return &obligations.ListObligationsResponse{}, nil
}

func newWarmupTestCache(t *testing.T, client *warmupPolicyClient, interval time.Duration) (*EntitlementPolicyCache, *otdfSDK.SDK) {
	t.Helper()
	sdk := &otdfSDK.SDK{Attributes: client, SubjectMapping: client, RegisteredResources: client, Obligations: client}
	mockCache, err := cache.TestCacheClient(mockCacheExpiry)
	require.NoError(t, err)
	c, err := NewEntitlementPolicyCache(t.Context(), l, access.NewEntitlementPolicyRetriever(sdk), mockCache, interval, false)
	require.NoError(t, err)
	t.Cleanup(c.Stop)
	return c, sdk
}

func TestEntitlementPolicyCache_ColdRequestsDoNotWaitForWarmup(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var enteredOnce, releaseOnce sync.Once
	client := &warmupPolicyClient{beforeAttributes: func(ctx context.Context) error {
		enteredOnce.Do(func() { close(entered) })
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}}
	c, sdk := newWarmupTestCache(t, client, time.Hour)
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	requestCtx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	var wg sync.WaitGroup
	// Collect results so assertions that stop the test run on the test goroutine.
	pdps := make([]*access.JustInTimePDP, 8)
	errs := make([]error, 8)
	for i := range 8 {
		wg.Go(func() {
			pdps[i], errs[i] = access.NewJustInTimePDP(requestCtx, l, sdk, c, false, false, false)
		})
	}
	wg.Wait()
	for i := range 8 {
		require.NoError(t, errs[i])
		require.NotNil(t, pdps[i])
	}
	require.NoError(t, requestCtx.Err(), "cold PDP construction must finish while full-policy retrieval is still blocked")
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("warmup must start immediately, not wait for the hourly timer")
	}
	assert.False(t, c.IsReady(t.Context()))
	assert.EqualValues(t, 1, client.attributeCalls.Load(), "requests must not launch their own full refreshes")
	// Canceling a completed request must not cancel the service-lifetime warmer.
	cancel()
	releaseOnce.Do(func() { close(release) })
	require.Eventually(t, func() bool { return c.IsReady(t.Context()) }, time.Second, time.Millisecond)
	assert.EqualValues(t, 1, client.attributeCalls.Load())
}

func TestEntitlementPolicyCache_StopCancelsWarmupAndRepeatedStartsCoalesce(t *testing.T) {
	entered, canceled := make(chan struct{}), make(chan struct{})
	client := &warmupPolicyClient{beforeAttributes: func(ctx context.Context) error {
		close(entered)
		<-ctx.Done()
		close(canceled)
		return ctx.Err()
	}}
	c, _ := newWarmupTestCache(t, client, time.Hour)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("warmup did not start")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() { assert.NoError(t, c.Start(t.Context())) })
	}
	wg.Wait()
	assert.EqualValues(t, 1, client.attributeCalls.Load())
	for range 8 {
		wg.Go(c.Stop)
	}
	wg.Wait()
	select {
	case <-canceled:
	default:
		t.Fatal("Stop must cancel the active SDK read before returning")
	}
	assert.False(t, c.IsReady(t.Context()))
}

func TestEntitlementPolicyCache_WarmupUsesConfiguredDeadline(t *testing.T) {
	expired := make(chan error, 1)
	client := &warmupPolicyClient{beforeAttributes: func(ctx context.Context) error {
		<-ctx.Done()
		select {
		case expired <- ctx.Err():
		default:
		}
		return ctx.Err()
	}}
	c, _ := newWarmupTestCache(t, client, 20*time.Millisecond)
	select {
	case err := <-expired:
		require.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(time.Second):
		t.Fatal("warmup must time out using the configured refresh interval")
	}
	assert.False(t, c.IsReady(t.Context()))
}

func TestEntitlementPolicyCache_FailedWarmupRetriesInBackground(t *testing.T) {
	first := make(chan struct{})
	var attempts atomic.Int32
	client := &warmupPolicyClient{beforeAttributes: func(context.Context) error {
		if attempts.Add(1) == 1 {
			close(first)
			return errors.New("policy temporarily unavailable")
		}
		return nil
	}}
	c, _ := newWarmupTestCache(t, client, 50*time.Millisecond)
	select {
	case <-first:
	case <-time.After(time.Second):
		t.Fatal("initial warmup did not start")
	}
	require.Eventually(t, func() bool { return c.IsReady(t.Context()) }, time.Second, time.Millisecond)
	assert.GreaterOrEqual(t, client.attributeCalls.Load(), int32(2))
}
