package utils

import (
	"encoding/json"
	"fmt"
	"github.com/jackc/pgtype"
	"io/ioutil"
	"math"
	"math/rand"
	"os"
	"reflect"
	"strings"
	"time"
)

var ISO8601 = "2006-01-02T15:04:05.999Z"

func EnsureDir(dirName string) error {
	err := os.MkdirAll(dirName, 0755)
	if err == nil || os.IsExist(err) {
		return nil
	} else {
		return err
	}
}

func WriteJsonToFile(data interface{}, path string) {
	d, _ := json.Marshal(data)
	WriteToFile(d, path)
}

func WriteIndentedJsonToFile(data interface{}, path string) {
	d, _ := json.MarshalIndent(data, " ", " ")
	WriteToFile(d, path)
}

func WriteToFile(data []byte, path string) {
	_ = ioutil.WriteFile(path, data, 0644)
}

func ReadFile(path string) ([]byte, error) {
	return ioutil.ReadFile(path)
}

func MilliToISO(timestamp int64) time.Time {
	return time.UnixMilli(timestamp)
}

func RandomInt(min int, max int) int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(max-min+1) + min
}

func RangeInt(start, stop int) []int {
	var d []int
	if stop < start {
		return d
	}
	for i := start; i <= stop; i++ {
		d = append(d, i)
	}
	return d
}

// Round rounds off a number to the next whole number.
func Round(num float64) int {
	return int(num + math.Copysign(0.5, num))
}

// RoundToFixed rounds a float64 to a given precision.
func RoundToFixed(num float64, precision int) float64 {
	output := math.Pow(10, float64(precision))
	return float64(Round(num*output)) / output
}

// ByteCountSI returns the formatted version of a size int64.
func ByteCountSI(b int64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB",
		float64(b)/float64(div), "kMGTPE"[exp])
}

// ToSnake converts a string to snake case.
func ToSnake(camel string) (snake string) {
	var b strings.Builder
	diff := 'a' - 'A'
	l := len(camel)
	for i, v := range camel {
		// A is 65, a is 97
		if v >= 'a' {
			b.WriteRune(v)
			continue
		}
		if (i != 0 || i == l-1) && (          // head and tail
		(i > 0 && rune(camel[i-1]) >= 'a') || // pre
			(i < l-1 && rune(camel[i+1]) >= 'a')) { //next
			b.WriteRune('_')
		}
		b.WriteRune(v + diff)
	}
	return b.String()
}

// SleepSeconds delays the execution using time.Sleep for given seconds.
func SleepSeconds(seconds int) {
	time.Sleep(time.Duration(seconds) * time.Second)
}

// TrackTime measures a function's execution time.
func TrackTime(funcName string) func() {
	start := time.Now()
	return func() {
		fmt.Printf("%s Completed in :  %v\n", funcName, time.Since(start))
	}
}

// RemoveSliceIndex removes an item of type int from index given in a slice.
func RemoveSliceIndex(s []int, index int) []int {
	return append(s[:index], s[index+1:]...)
}

// MinSlice returns the least number in the given slice.
func MinSlice(weeks []int) int {
	m := weeks[0]
	for _, e := range weeks {
		if e < m {
			m = e
		}
	}
	return m
}

// MaxSlice returns the largest number in the given slice.
func MaxSlice(weeks []int) int {
	m := weeks[0]
	for _, e := range weeks {
		if e > m {
			m = e
		}
	}
	return m
}

// SumSlice returns sum of all integers in a slice.
func SumSlice(data []int) int {
	var a int
	for _, v := range data {
		a += v
	}
	return a
}

func SliceIntExists(s []int, it int) bool {
	for _, k := range s {
		if k == it {
			return true
		}
	}
	return false
}

func SliceStringExists(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

func SliceFloatExists(s []float64, flt float64) bool {
	for _, v := range s {
		if v == flt {
			return true
		}
	}

	return false
}

// SubSlice return items in slice b but not in a
func SubSlice(a []int, b []int) []int {
	var c []int
	c = []int{}
	for _, x := range b {
		v := false
		for _, y := range a {
			if y == x {
				v = true
				break
			}
		}
		if !v {
			c = append(c, x)
		}
	}
	return c
}

// EqualSliceInt checks if two slices of int type are equal.
func EqualSliceInt(a []int, b []int) bool {
	if len(a) != len(b) {
		return false
	}

	for i, j := range a {
		if b[i] != j {
			return false
		}
	}
	return true
}

// MapCount counts the number of appearances of an int in a given slice.
func MapCount(values []int) map[int]int {
	r := make(map[int]int)
	for _, k := range values {
		_, ok := r[k]
		if ok {
			r[k] += 1
		} else {
			r[k] = 1
		}
	}
	return r
}

func ViewStructFields(a interface{}) {
	v := reflect.ValueOf(a)
	v = v.Elem()
	sf := v.Type()
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		fs := sf.Field(i)
		fmt.Println(fs.Name, f.Interface())
	}
}

func PrependInt(x []int, y int) []int {
	x = append(x, 0)
	copy(x[1:], x)
	x[0] = y
	return x
}

func GoodDecoder(data []byte, a interface{}) error {
	err := json.Unmarshal(data, a)
	if jsonError, ok := err.(*json.UnmarshalTypeError); ok {
		line, character, lcErr := lineAndCharacter(string(data), int(jsonError.Offset))
		return fmt.Errorf("test %s failed with error: The JSON type '%v' cannot be converted into the Go '%v' type on struct '%s', field '%v'. See input file line %d, character %d %v\n", string(data), jsonError.Value, jsonError.Type.Name(), jsonError.Struct, jsonError.Field, line, character, lcErr)
	}
	return err
}

func GoodEncoder(a interface{}) []byte {
	d, _ := json.Marshal(a)
	return d
}

func lineAndCharacter(input string, offset int) (line int, character int, err error) {
	lf := rune(0x0A)

	if offset > len(input) || offset < 0 {
		return 0, 0, fmt.Errorf("Couldn't find offset %d within the input.", offset)
	}

	// Humans tend to count from 1.
	line = 1

	for i, b := range input {
		if b == lf {
			line++
			character = 0
		}
		character++
		if i == offset {
			break
		}
	}

	return line, character, nil
}

//type JSONTime struct {
//	time.Time
//}
//
//func (t JSONTime) MarshalJSON() ([]byte, error) {
//	stamp := fmt.Sprintf("\"%s\"", t.Format(ISO8601))
//	return []byte(stamp), nil
//}

type JSONTime struct {
	time.Time
}

func (t JSONTime) MarshalJSON() ([]byte, error) {
	ay := t.Format(ISO8601)
	l := len(ay)
	idx := strings.Index(ay, ".")
	if (idx) < 0 {
		ay = ay[:l-1] + ".000Z"
	} else {
		if idx != l-5 {
			y := idx - (l - 5)
			ay = ay[:l-1] + (strings.Repeat("0", y)) + "Z"
		}
	}
	return []byte(fmt.Sprintf("\"%s\"", ay)), nil
}

func (t *JSONTime) DecodeBinary(ci *pgtype.ConnInfo, src []byte) error {
	c := pgtype.Timestamp{}
	c.DecodeBinary(ci, src)
	t.Time = c.Time
	return nil
}

func (f *JSONTime) EncodeBinary(ci *pgtype.ConnInfo, buf []byte) []byte {
	c := pgtype.Timestamp{Time: f.Time}
	bf, _ := c.EncodeBinary(ci, buf)
	return bf
}

func (f *JSONTime) EncodeText(ci *pgtype.ConnInfo, buf []byte) []byte {
	c := pgtype.Timestamp{Time: f.Time}
	bf, _ := c.EncodeText(ci, buf)
	return bf
}

type JSONDate struct {
	time.Time
}

func (t JSONDate) MarshalJSON() ([]byte, error) {
	ay := t.Format(ISO8601)
	l := len(ay)
	idx := strings.Index(ay, ".")
	if (idx) < 0 {
		ay = ay[:l-1] + ".000Z"
	} else {
		if idx != l-5 {
			y := idx - (l - 5)
			ay = ay[:l-1] + (strings.Repeat("0", y)) + "Z"
		}
	}
	return []byte(fmt.Sprintf("\"%s\"", ay)), nil
}

func (t *JSONDate) DecodeBinary(ci *pgtype.ConnInfo, src []byte) error {
	c := pgtype.Date{}
	c.DecodeBinary(ci, src)
	t.Time = c.Time
	return nil
}

func (f *JSONDate) EncodeBinary(ci *pgtype.ConnInfo, buf []byte) []byte {
	c := pgtype.Date{Time: f.Time}
	bf, _ := c.EncodeBinary(ci, buf)
	return bf
}

func (f *JSONDate) EncodeText(ci *pgtype.ConnInfo, buf []byte) []byte {
	c := pgtype.Date{Time: f.Time}
	bf, _ := c.EncodeText(ci, buf)
	return bf
}

func DateEqual(time1, time2 time.Time) bool {
	xx, yy, zz := time1.Date()
	xx_, yy_, zz_ := time2.Date()
	if xx == xx_ && yy == yy_ && zz == zz_ {
		return true
	}
	return false
}
