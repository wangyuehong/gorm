package logger

import (
	"database/sql/driver"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"gorm.io/gorm/utils"
)

const (
	tmFmtWithMS = "2006-01-02 15:04:05.999"
	tmFmtZero   = "0000-00-00 00:00:00"
	nullStr     = "NULL"
)

func isPrintable(s string) bool {
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// A list of Go types that should be converted to SQL primitives
var convertibleTypes = []reflect.Type{reflect.TypeOf(time.Time{}), reflect.TypeOf(false), reflect.TypeOf([]byte{})}

// RegEx matches only numeric values
var numericPlaceholderRe = regexp.MustCompile(`\$\d+\$`)

// default sql param formater
var defaultParamFormater ParamFormater = &paramFormater{
	timeFormat:       tmFmtWithMS,
	zeroTimeStr:      tmFmtZero,
	nullStr:          nullStr,
	convertibleTypes: convertibleTypes,
}

func formatParam(val interface{}, escaper string) string {
	return defaultParamFormater.Format(val, escaper)
}

// ExplainSQL generate SQL string with given parameters, the generated SQL is expected to be used in logger, execute it might introduce a SQL injection vulnerability
func ExplainSQL(sql string, numericPlaceholder *regexp.Regexp, escaper string, avars ...interface{}) string {
	vars := make([]string, len(avars))
	for i, val := range avars {
		vars[i] = formatParam(val, escaper)
	}

	if numericPlaceholder == nil {
		var idx int
		var newSQL strings.Builder

		for _, v := range []byte(sql) {
			if v == '?' {
				if len(vars) > idx {
					newSQL.WriteString(vars[idx])
					idx++
					continue
				}
			}
			newSQL.WriteByte(v)
		}

		sql = newSQL.String()
	} else {
		sql = numericPlaceholder.ReplaceAllString(sql, "$$$1$$")

		sql = numericPlaceholderRe.ReplaceAllStringFunc(sql, func(v string) string {
			num := v[1 : len(v)-1]
			n, _ := strconv.Atoi(num)

			// position var start from 1 ($1, $2)
			n -= 1
			if n >= 0 && n <= len(vars)-1 {
				return vars[n]
			}
			return v
		})
	}

	return sql
}

// ParamFormater is used to format SQL parameters.
type ParamFormater interface {
	// Format formats the given parameter value with escaper.
	Format(val interface{}, escaper string) string
}

// paramFormater is the default implementation of ParamFormater
type paramFormater struct {
	timeFormat string
	// zeroTimeStr is used as formated value for zero time, if leave it empty, use timeFormat to format zero time.
	zeroTimeStr      string
	nullStr          string
	convertibleTypes []reflect.Type
}

// Format formats the given parameter with escape for SQL log
func (p *paramFormater) Format(val interface{}, escaper string) string {
	switch v := val.(type) {
	case bool:
		return strconv.FormatBool(v)
	case time.Time:
		return p.formatTime(v, escaper)
	case *time.Time:
		if v == nil {
			return p.formatNull()
		}
		return p.formatTime(*v, escaper)
	case driver.Valuer:
		if isNilValue(v) {
			return p.formatNull()
		}
		r, _ := v.Value()
		return p.Format(r, escaper)
	case fmt.Stringer:
		reflectValue := reflect.ValueOf(v)
		switch reflectValue.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			return fmt.Sprintf("%d", reflectValue.Interface())
		case reflect.Float32, reflect.Float64:
			return fmt.Sprintf("%.6f", reflectValue.Interface())
		case reflect.Bool:
			return fmt.Sprintf("%t", reflectValue.Interface())
		case reflect.String:
			return p.escapeStr(fmt.Sprintf("%v", v), escaper)
		default:
			if isNilValue(v) {
				return p.formatNull()
			}
			return p.escapeStr(fmt.Sprintf("%v", v), escaper)
		}
	case []byte:
		if s := string(v); isPrintable(s) {
			return p.escapeStr(s, escaper)
		}
		return p.escape("<binary>", escaper)
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return utils.ToString(v)
	case float32:
		return strconv.FormatFloat(float64(v), 'f', -1, 32)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case string:
		return p.escapeStr(v, escaper)
	default:
		if isNilValue(v) {
			return p.formatNull()
		}

		if valuer, ok := v.(driver.Valuer); ok {
			v, _ = valuer.Value()
			return p.Format(v, escaper)
		}

		rv := reflect.ValueOf(v)
		if rv.Kind() == reflect.Ptr && !rv.IsZero() {
			return p.Format(reflect.Indirect(rv).Interface(), escaper)
		}

		for _, t := range p.convertibleTypes {
			if rv.Type().ConvertibleTo(t) {
				return p.Format(rv.Convert(t).Interface(), escaper)
			}
		}

		return p.escapeStr(fmt.Sprint(v), escaper)
	}
}

func (p *paramFormater) formatTime(t time.Time, escaper string) string {
	var strVal string
	if t.IsZero() && p.zeroTimeStr != "" {
		strVal = p.zeroTimeStr
	} else {
		strVal = t.Format(p.timeFormat)
	}

	return p.escapeStr(strVal, escaper)
}

func (p *paramFormater) formatNull() string { return p.nullStr }

func (p *paramFormater) escapeStr(s, escaper string) string {
	s = strings.ReplaceAll(s, escaper, "\\"+escaper)
	return p.escape(s, escaper)
}

func (*paramFormater) escape(v, escaper string) string {
	return escaper + v + escaper
}

func isNilValue(v interface{}) bool {
	if v == nil {
		return true
	}

	rv := reflect.ValueOf(v)
	notNil := rv.IsValid() && ((rv.Kind() == reflect.Ptr && !rv.IsNil()) || rv.Kind() != reflect.Ptr)
	return !notNil
}
