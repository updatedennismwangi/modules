package orm

import (
	"context"
	"fmt"
	"github.com/fatih/structs"
	"github.com/georgysavva/scany/pgxscan"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	. "github.com/updatedennismwangi/log"
	. "github.com/updatedennismwangi/utils"
	"reflect"
	"strings"
	"time"
)

func OrmQuery(conn *pgxpool.Pool, arr interface{}, sql string) error {
	//defer TrackTime("ORM OrmQuery")()
	err := pgxscan.Select(context.Background(), conn, arr, sql)
	if err != nil {
		Log(INFO, "ORM QUERY : %v %s", err, sql)
		return err
	}
	return nil
}

func OrmAll(conn *pgxpool.Pool, f interface{}, arr interface{}, limit int) error {
	v := reflect.ValueOf(f)
	v = v.Elem()
	if v.Kind() != reflect.Struct {
		return fmt.Errorf("not struct; is %T", f)
	}

	table := OrmTableName(v)
	sql := fmt.Sprintf("SELECT * FROM %s  LIMIT %d;", table, limit)

	err := pgxscan.Select(context.Background(), conn, arr, sql)
	if err != nil {
		Log(INFO, "ORM ALL : %v %s", err, sql)
		return err
	}
	return nil
}

func OrmCreate(conn *pgxpool.Pool, f interface{}) error {
	//defer TrackTime("ORM Create")()
	v := reflect.ValueOf(f)
	if v.Kind() != reflect.Ptr {
		return fmt.Errorf("not ptr; is %T", f)
	}
	v = v.Elem()
	if v.Kind() != reflect.Struct {
		return fmt.Errorf("not struct; is %T", f)
	}

	t := v.Type()
	table := OrmTableName(v)
	var columns []string
	var returningColumns []string
	var returningValues []interface{}
	var values []interface{}
	valuesIdx := 1
	var valuesSql string
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		column := ToSnake(sf.Name)
		if column == "tb_name" {
			continue
		}
		var value interface{}
		value = v.Field(i).Interface()
		auto := sf.Tag.Get("auto")
		if len(auto) > 0 {
			returningColumns = append(returningColumns, column)
			returningValues = append(returningValues, v.Field(i).Addr().Interface())
			continue
		}

		tm := sf.Tag.Get("time")
		if len(tm) > 0 {
			switch value.(type) {
			case JSONTime:
				{
					value = value.(JSONTime).Time
				}
			case JSONDate:
				{
					value = value.(JSONDate).Time.Format("2006/01/02")
				}
			}
			format := sf.Tag.Get("format")
			if len(format) > 0 {
				value = value.(time.Time).Format(format)
			}
		}

		js := sf.Tag.Get("js")
		if len(js) > 0 {
			value = structs.Map(value.(interface{}))
		}

		valuesSql = fmt.Sprintf("%s, $%d", valuesSql, valuesIdx)
		columns = append(columns, column)
		values = append(values, value)
		valuesIdx += 1
	}
	columnsSql := strings.Join(columns, ", ")
	valuesSql = valuesSql[2:]
	rt := ""
	if len(returningColumns) > 0 {
		rt = "RETURNING " + strings.Join(returningColumns, ", ")
	}
	sql := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s) %s;", table, columnsSql, valuesSql, rt)

	//log.Println(sql, valuesIdx-1, values)
	ll := conn.QueryRow(context.Background(), sql, values...)
	err := ll.Scan(returningValues...)
	if err != nil && err != pgx.ErrNoRows {
		Log(INFO, "ORM CREATE : %v %s %v", err, sql, values)
		return err
	}
	return nil
}

func OrmUpdate(conn *pgxpool.Pool, f interface{}, args ...string) error {
	//defer TrackTime("ORM Update")()
	v := reflect.ValueOf(f)
	if v.Kind() != reflect.Ptr {
		return fmt.Errorf("not ptr; is %T", f)
	}
	v = v.Elem()
	if v.Kind() != reflect.Struct {
		return fmt.Errorf("not struct; is %T", f)
	}

	t := v.Type()
	table := OrmTableName(v)
	// End setup Table

	var columns []string
	var values []interface{}
	valuesIdx := 1
	var valuesSql string
	var whereSql string

	for _, cl := range args {
		sf, _ := t.FieldByName(cl)
		column := ToSnake(sf.Name)
		value := v.Field(sf.Index[0]).Interface()
		tm := sf.Tag.Get("time")
		if len(tm) > 0 {
			yk := strings.Split(tm, ",")
			if yk[1] == "update" {
				value = time.Now()
			}
			switch value.(type) {
			case JSONTime:
				{
					value = value.(JSONTime).Time
				}
			case JSONDate:
				{
					value = value.(JSONDate).Time.Format("2006/01/02")
				}
			}
			format := sf.Tag.Get("format")
			if len(format) > 0 {
				value = value.(time.Time).Format(format)
			}
		}

		js := sf.Tag.Get("js")
		if len(js) > 0 {
			value = structs.Map(value.(interface{}))
		}

		valuesSql = fmt.Sprintf("%s, %s=$%d", valuesSql, column, valuesIdx)
		columns = append(columns, column)
		values = append(values, value)
		valuesIdx += 1
	}

	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		column := ToSnake(sf.Name)
		if column == "tb_name" {
			continue
		}
		value := v.Field(i).Interface()

		key := sf.Tag.Get("key")
		if len(key) < 1 {
			continue
		}

		//a := reflect.Zero(t.Field(i).Type)
		//if a.Interface() == value {
		//	continue
		//}

		whereSql = fmt.Sprintf("%s AND %s=$%d", whereSql, column, valuesIdx)
		values = append(values, value)
		valuesIdx += 1
	}

	valuesSql = valuesSql[2:]
	whereSql = whereSql[5:]
	sql := fmt.Sprintf("UPDATE %s SET %s WHERE %s;", table, valuesSql, whereSql)

	//fmt.Println(sql, valuesIdx-1, values)
	_, err := conn.Exec(context.Background(), sql, values...)
	if err != nil {
		Log(INFO, "ORM UPDATE : %v %s %v", err, sql, values)
		return err
	}
	return nil
}

func OrmUpdateId(conn *pgxpool.Pool, f interface{}, args ...string) error {
	//defer TrackTime("ORM Update")()
	v := reflect.ValueOf(f)
	if v.Kind() != reflect.Ptr {
		return fmt.Errorf("not ptr; is %T", f)
	}
	v = v.Elem()
	if v.Kind() != reflect.Struct {
		return fmt.Errorf("not struct; is %T", f)
	}

	t := v.Type()
	table := OrmTableName(v)
	// End setup Table

	var columns []string
	var values []interface{}
	valuesIdx := 1
	var valuesSql string
	var whereSql string

	for _, cl := range args {
		sf, _ := t.FieldByName(cl)
		column := ToSnake(sf.Name)
		value := v.Field(sf.Index[0]).Interface()
		tm := sf.Tag.Get("time")
		if len(tm) > 0 {
			yk := strings.Split(tm, ",")
			if len(yk) > 1 {
				if yk[1] == "update" {
					value = time.Now()
				}
			}
			switch value.(type) {
			case JSONTime:
				{
					value = value.(JSONTime).Time
				}
			case JSONDate:
				{
					value = value.(JSONDate).Time.Format("2006/01/02")
				}
			}
			format := sf.Tag.Get("format")
			if len(format) > 0 {
				value = value.(time.Time).Format(format)
			}
		}

		js := sf.Tag.Get("js")
		if len(js) > 0 {
			value = structs.Map(value.(interface{}))
		}

		valuesSql = fmt.Sprintf("%s, %s=$%d", valuesSql, column, valuesIdx)
		columns = append(columns, column)
		values = append(values, value)
		valuesIdx += 1
	}

	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		column := ToSnake(sf.Name)
		if column == "tb_name" {
			continue
		}
		value := v.Field(i).Interface()

		key := sf.Tag.Get("id")
		if len(key) < 1 {
			continue
		}

		//a := reflect.Zero(t.Field(i).Type)
		//if a.Interface() == value {
		//	continue
		//}

		whereSql = fmt.Sprintf("%s AND %s=$%d", whereSql, column, valuesIdx)
		values = append(values, value)
		valuesIdx += 1
	}
	if len(valuesSql) < 2 {
		fmt.Println("warning update request with no specific field to update")
	} else {
		valuesSql = valuesSql[2:]
	}
	whereSql = whereSql[5:]
	sql := fmt.Sprintf("UPDATE %s SET %s WHERE %s;", table, valuesSql, whereSql)
	_, err := conn.Exec(context.Background(), sql, values...)
	if err != nil {
		Log(INFO, "ORM UPDATE : %v %s %v", err, sql, values)
		return err
	}
	return nil
}

func OrmGet(conn *pgxpool.Pool, f interface{}) error {
	//defer TrackTime("ORM Get")()
	v := reflect.ValueOf(f)
	if v.Kind() != reflect.Ptr {
		return fmt.Errorf("not ptr; is %T", f)
	}
	v = v.Elem()
	if v.Kind() != reflect.Struct {
		return fmt.Errorf("not struct; is %T", f)
	}

	t := v.Type()
	table := OrmTableName(v)
	var clauseSql string
	var returningColumns []string
	var returningValues []interface{}
	var values []interface{}
	valuesIdx := 1

	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		column := ToSnake(sf.Name)
		if column == "tb_name" {
			continue
		}
		value := v.Field(i).Interface()
		returningColumns = append(returningColumns, column)
		returningValues = append(returningValues, v.Field(i).Addr().Interface())
		key := sf.Tag.Get("key")
		if len(key) < 1 {
			continue
		}
		a := reflect.Zero(t.Field(i).Type)
		if a.Interface() == value {
			continue
		}

		tm := sf.Tag.Get("time")
		if len(tm) > 0 {
			switch value.(type) {
			case JSONTime:
				{
					value = value.(JSONTime).Time
				}
			case JSONDate:
				{
					value = value.(JSONDate).Time.Format("2006/01/02")
				}
			}
			format := sf.Tag.Get("format")
			if len(format) > 0 {
				value = value.(time.Time).Format(format)
			}
		}

		js := sf.Tag.Get("js")
		if len(js) > 0 {
			value = structs.Map(value.(interface{}))
		}

		clauseSql = fmt.Sprintf("%s AND %s=$%d", clauseSql, column, valuesIdx)
		values = append(values, value)
		valuesIdx += 1
	}

	clauseSql = fmt.Sprintf("%s", clauseSql[5:])
	sql := fmt.Sprintf("SELECT * FROM %s WHERE %s;", table, clauseSql)

	//log.Println(sql, valuesIdx-1, values)
	ll := conn.QueryRow(context.Background(), sql, values...)
	err := ll.Scan(returningValues...)
	if err != nil {
		Log(INFO, "ORM GET : %v %s %v", err, sql, values)
		return err
	}
	return nil
}

func OrmFilter(conn *pgxpool.Pool, f interface{}, arr interface{}, limit int, args ...string) error {
	//defer TrackTime("ORM OrmFilter")()
	//fT := reflect.TypeOf(f)
	//ftSlice := reflect.SliceOf(fT)
	//ptr := reflect.New(ftSlice)
	//ptr.Elem().Set(reflect.MakeSlice(ftSlice, 0, limit))
	//arr3 := ptr.Interface()
	var clauseSql string
	var values []interface{}
	valuesIdx := 1

	v := reflect.ValueOf(f)
	v = v.Elem()
	if v.Kind() != reflect.Struct {
		return fmt.Errorf("not struct; is %T", f)
	}

	t := v.Type()
	table := OrmTableName(v)
	for _, cl := range args {
		sf, _ := t.FieldByName(cl)
		column := ToSnake(sf.Name)
		if column == "tb_name" {
			continue
		}
		value := v.Field(sf.Index[0]).Interface()
		tm := sf.Tag.Get("time")
		if len(tm) > 0 {
			switch value.(type) {
			case JSONTime:
				{
					value = value.(JSONTime).Time
				}
			case JSONDate:
				{
					value = value.(JSONDate).Time.Format("2006/01/02")
				}
			}
			format := sf.Tag.Get("format")
			if len(format) > 0 {
				value = value.(time.Time).Format(format)
			}
		}
		js := sf.Tag.Get("js")
		if len(js) > 0 {
			value = structs.Map(value.(interface{}))
		}
		clauseSql = fmt.Sprintf("%s AND %s=$%d", clauseSql, column, valuesIdx)
		values = append(values, value)
		valuesIdx += 1
	}

	clauseSql = fmt.Sprintf("%s", clauseSql[5:])
	sql := fmt.Sprintf("SELECT * FROM %s WHERE %s LIMIT %d;", table, clauseSql, limit)

	//log.Println(sql, valuesIdx-1, values)
	err := pgxscan.Select(context.Background(), conn, arr, sql, values...)
	if err != nil {
		Log(INFO, "ORM FILTER : %v %s %v", err, sql, values)
		return err
	}
	return nil
}

func OrmSave(conn *pgxpool.Pool, f interface{}) error {
	//defer TrackTime("ORM OrmSave")()
	v := reflect.ValueOf(f)
	if v.Kind() != reflect.Ptr {
		return fmt.Errorf("not ptr; is %T", f)
	}
	v = v.Elem()
	if v.Kind() != reflect.Struct {
		return fmt.Errorf("not struct; is %T", f)
	}

	t := v.Type()
	table := OrmTableName(v)
	// End setup Table

	var columns []string
	var values []interface{}
	valuesIdx := 1
	var valuesSql string

	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		column := ToSnake(sf.Name)
		if column == "tb_name" {
			continue
		}
		value := v.Field(i).Interface()
		tm := sf.Tag.Get("time")
		if len(tm) > 0 {
			switch value.(type) {
			case JSONTime:
				{
					value = value.(JSONTime).Time
				}
			case JSONDate:
				{
					value = value.(JSONDate).Time.Format("2006/01/02")
				}
			}
			format := sf.Tag.Get("format")
			if len(format) > 0 {
				value = value.(time.Time).Format(format)
			}
		}
		js := sf.Tag.Get("js")
		if len(js) > 0 {
			value = structs.Map(value.(interface{}))
		}
		valuesSql = fmt.Sprintf("%s, %s=$%d", valuesSql, column, valuesIdx)
		columns = append(columns, column)
		values = append(values, value)
		valuesIdx += 1
	}

	sf, _ := t.FieldByName("ID")
	column := ToSnake(sf.Name)
	value := v.Field(sf.Index[0]).Interface()

	valuesSql = valuesSql[2:]
	sql := fmt.Sprintf("UPDATE %s SET %s WHERE %s=%v;", table, valuesSql, column, value)

	//log.Println(sql, valuesIdx-1, values)
	_, err := conn.Exec(context.Background(), sql, values...)
	if err != nil {
		Log(INFO, "ORM SAVE : %v %s %v", err, sql, values)
		return err
	}
	return nil
}

func OrmDelete(conn *pgxpool.Pool, f interface{}) error {
	//defer TrackTime("ORM OrmDelete")()
	v := reflect.ValueOf(f)
	if v.Kind() != reflect.Ptr {
		return fmt.Errorf("not ptr; is %T", f)
	}
	v = v.Elem()
	if v.Kind() != reflect.Struct {
		return fmt.Errorf("not struct; is %T", f)
	}

	t := v.Type()
	table := OrmTableName(v)
	// End setup Table

	var values []interface{}
	valuesIdx := 1

	var whereSql string

	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		column := ToSnake(sf.Name)
		if column == "tb_name" {
			continue
		}
		value := v.Field(i).Interface()

		key := sf.Tag.Get("key")
		if len(key) < 1 {
			continue
		}

		tm := sf.Tag.Get("time")
		if len(tm) > 0 {
			switch value.(type) {
			case JSONTime:
				{
					value = value.(JSONTime).Time
				}
			case JSONDate:
				{
					value = value.(JSONDate).Time.Format("2006/01/02")
				}
			}
			format := sf.Tag.Get("format")
			if len(format) > 0 {
				value = value.(time.Time).Format(format)
			}
		}
		js := sf.Tag.Get("js")
		if len(js) > 0 {
			value = structs.Map(value.(interface{}))
		}

		a := reflect.Zero(t.Field(i).Type)
		if a.Interface() == value {
			continue
		}
		whereSql = fmt.Sprintf("%s AND %s=$%d", whereSql, column, valuesIdx)
		values = append(values, value)
		valuesIdx += 1
	}

	whereSql = whereSql[5:]
	sql := fmt.Sprintf("DELETE FROM %s WHERE %s;", table, whereSql)

	//log.Println(sql, valuesIdx-1, values)
	_, err := conn.Exec(context.Background(), sql, values...)
	if err != nil {
		Log(INFO, "ORM DELETE : %v %s %v", err, sql, values)
		return err
	}
	return nil
}

func OrmTableName(v reflect.Value) string {
	var table string
	cb := v.MethodByName("TbName")
	if cb.IsValid() {
		x := cb.Call([]reflect.Value{})
		table = x[0].Interface().(string)
	} else {
		table = v.Type().Name()
		table = table[0 : len(table)-5]
		table = ToSnake(fmt.Sprintf("%ss", table))
	}
	return table
}
