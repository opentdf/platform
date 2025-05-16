package cucumbersimple


import (
	"fmt"
	"math"
)

const (
	maxNanos = 999999999
)

type Money struct {

	// The three-letter currency code defined in ISO 4217.
	CurrencyCode string `protobuf:"bytes,1,opt,name=currency_code,json=currencyCode,proto3" json:"currency_code,omitempty"`

	// The whole units of the amount.
	// For example if `currencyCode` is `"USD"`, then 1 unit is one US dollar.
	Units int64 `protobuf:"varint,2,opt,name=units,proto3" json:"units,omitempty"`

	// Number of nano (10^-9) units of the amount.
	// The value must be between -999,999,999 and +999,999,999 inclusive.
	// If `units` is positive, `nanos` must be positive or zero.
	// If `units` is zero, `nanos` can be positive, zero, or negative.
	// If `units` is negative, `nanos` must be negative or zero.
	// For example $-1.75 is represented as `units`=-1 and `nanos`=-750,000,000.
	Nanos int32 `protobuf:"varint,3,opt,name=nanos,proto3" json:"nanos,omitempty"`
}

func NewMoney(currencyCode string, units int64, nanos int32) (Money, error) {
	if units < 0 && nanos > 0 {
		return Money{}, fmt.Errorf("cannot mix negative units and positive nanos")
	}
	if nanos < 0 && units > 0 {
		return Money{}, fmt.Errorf("cannot mix negative nanos and positive units")
	}
	return Money{CurrencyCode: currencyCode, Units: units, Nanos: nanos}, nil
}

var base = int64(maxNanos + 1)

// handle nanos as int64, borrowing/carrying over to units as needed
func carry(totalUnits int64, totalNanos int64) (int64, int32) {
	additionalUnits := totalNanos / base
	remainingNanos := totalNanos % base
	return totalUnits + additionalUnits, int32(remainingNanos)
}

func (m Money) Add(money Money) (Money, error) {
	if m.CurrencyCode != money.CurrencyCode {
		return Money{}, fmt.Errorf("you must convert values to common currency code using current exchange rates before adding")
	}
	units, nanos := carry(m.Units+money.Units, int64(m.Nanos)+int64(money.Nanos))
	return Money{m.CurrencyCode, units, nanos}, nil
}

func (m Money) Subtract(money Money) (Money, error) {
	negative := Money{
		CurrencyCode: money.CurrencyCode,
		Units:        money.Units * -1,
		Nanos:        money.Nanos * -1,
	}
	result, err := m.Add(negative)
	return result, err
}

// Take an input x and multiply it by m * 10 ^ n, where m is a whole number.
// Return the quotient and remainder of the result after dividing by 10 ^ n.
func applyFactorOfTen(x int64, m int, n int) (int64, int64) {
	factor := math.Pow10(n)
	product := float64(x) * float64(m) * factor
	asNanos := product * float64(base)
	i := int64(asNanos)
	return i / base, i % base
}

func (m Money) Multiply(mantissa int, exponent int) Money {
	wholeUnits, fractionalUnits := applyFactorOfTen(m.Units, mantissa, exponent)
	wholeNanos, fractionalNanos := applyFactorOfTen(int64(m.Nanos), mantissa, exponent)
	totalNanos := fractionalUnits + wholeNanos
	// round up nanos if necessary
	if fractionalNanos >= base/2 {
		totalNanos += 1
	}
	units, nanos := carry(wholeUnits, totalNanos)
	return Money{m.CurrencyCode, units, nanos}
}

func (m Money) IsNegative() bool {
	return m.Nanos < 0 || m.Units < 0
}

func (m1 Money) IsEqual(m2 Money) bool {
	return m1.CurrencyCode == m2.CurrencyCode && m1.Units == m2.Units && m1.Nanos == m2.Nanos
}

func (m Money) String() string {
	return fmt.Sprintf("%s %d.%d", m.CurrencyCode, m.Units, m.Nanos)
}

type Account interface {
	Balance() Money
	Deposit(Money) error
	Withdraw(Money) error
}
