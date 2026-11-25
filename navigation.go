package main

import (
	"context"
	"math"
	"math/rand/v2"
	"time"

	"local/aistudio-signer/transport"
)

// Adapted from v0.3.13 navigation_timing.go. Connection durations and document
// completion are observed; parsing/render offsets and encoded size are the
// reference model's estimates, not measured browser rendering or transfer bytes.
type pageLoad struct {
	url, protocol string
	started       time.Time
	connection    transport.ConnectionTiming
	end           time.Duration
	decoded       int
}

const firefoxEncodedRatio = 0.1943

func navigationTiming(load pageLoad) (map[string]any, int) {
	at := func(moment time.Time) int { return int(moment.Sub(load.started).Milliseconds()) }
	fetch := rand.IntN(2)
	lookup, lookupEnd, connect, connectEnd := fetch, fetch, fetch, fetch
	request := fetch + 2 + rand.IntN(12)
	response := max(request+1, int(load.end.Milliseconds()))
	headers := response
	if timing := load.connection; timing.Dialed {
		lookup = fetch + rand.IntN(14)
		lookupEnd = lookup
		if !timing.DNSStart.IsZero() && !timing.DNSDone.IsZero() {
			lookupEnd += int(timing.DNSDone.Sub(timing.DNSStart).Milliseconds())
		}
		connect = lookupEnd + rand.IntN(2)
		connectEnd = connect
		if !timing.ConnectStart.IsZero() && !timing.ConnectDone.IsZero() {
			connectEnd += int(timing.ConnectDone.Sub(timing.ConnectStart).Milliseconds())
		}
		request = connectEnd + 1 + rand.IntN(4)
		headers = request
		if !timing.Tunneled.IsZero() {
			headers = max(request, connectEnd+at(timing.Tunneled)-at(timing.ConnectDone))
		}
		response = max(response, headers)
	}
	encoded := int(math.Round(float64(load.decoded)*firefoxEncodedRatio)) + rand.IntN(13) - 6
	entry := map[string]any{
		"name": load.url, "startTime": 0, "nextHopProtocol": load.protocol,
		"fetchStart": fetch, "domainLookupStart": lookup, "domainLookupEnd": lookupEnd,
		"connectStart": connect, "connectEnd": connectEnd, "secureConnectionStart": connectEnd,
		"requestStart": request, "finalResponseHeadersStart": headers,
		"responseStart": response, "responseEnd": response,
		"transferSize": encoded + 300, "encodedBodySize": encoded, "decodedBodySize": load.decoded,
	}
	return entry, response + pick(0, 0, 1, 1, 1, 1, 1, 1, 2, 2, 2, 3)
}

func documentTiming(entry map[string]any, resources time.Duration) {
	ready := max(entry["responseEnd"].(int), int(resources.Milliseconds()))
	interactive := ready + max(200, lognormal(6.13, 0.62))
	complete := interactive + lognormal(6.96, 0.48)
	loadEnd := complete + pick(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
	entry["domInteractive"] = interactive
	entry["domContentLoadedEventStart"] = interactive
	entry["domContentLoadedEventEnd"] = interactive + pick(0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 4)
	entry["domComplete"] = complete
	entry["loadEventStart"] = complete
	entry["loadEventEnd"] = loadEnd
	entry["duration"] = loadEnd
}

func lognormal(mu, sigma float64) int {
	return int(math.Round(math.Exp(mu + sigma*rand.NormFloat64())))
}

func pick(values ...int) int {
	return values[rand.IntN(len(values))]
}

// Retained columns: Waa/Create and catalogue dispatch relative to logging
// dispatch. The source's unused preferences/Drive/promotions calls are omitted.
func contextStartupOffsets() (time.Duration, time.Duration) {
	samples := [][2]int{{119, 150}, {36, 85}, {53, 120}, {38, 95}}
	sample := samples[rand.IntN(len(samples))]
	scale := 0.9 + 0.2*rand.Float64()
	return time.Duration(float64(sample[0])*scale*float64(time.Millisecond)),
		time.Duration(float64(sample[1])*scale*float64(time.Millisecond))
}

func waitUntil(ctx context.Context, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if delay := time.Until(at); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return ctx.Err()
}
