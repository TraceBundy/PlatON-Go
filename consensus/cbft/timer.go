package cbft

import "time"

type viewTimer struct {
	//Timer last timeout
	deadline time.Time
	timer    *time.Timer

	//Time window length calculation module
	timeInterval viewTimeInterval
}

func (t viewTimer) setupTimer() {

}

// Calculate the time window of each view，time=b*e^m
type viewTimeInterval struct {
	baseMs       uint64
	exponentBase float64
	maxExponent  uint64
}

func (vt viewTimeInterval) getViewTimeInterval(viewInterval uint64) time.Duration {
	return 0
}