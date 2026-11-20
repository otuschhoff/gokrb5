package ndr

import (
	"reflect"
	"slices"
	"strings"
)

const ndrNameSpace = "ndr"

type tags struct {
	Values []string
	Map    map[string]string
}

// parse the struct field tags and extract the ndr related ones.
// format of tag ndr:"value,key:value1,value2"
func parseTags(st reflect.StructTag) tags {
	s := st.Get(ndrNameSpace)
	t := tags{
		Values: []string{},
		Map:    make(map[string]string),
	}
	if s != "" {
		ndrTags := strings.Trim(s, `"`)
		for tag := range strings.SplitSeq(ndrTags, ",") {
			if key, value, ok := strings.Cut(tag, ":"); ok {
				t.Map[key] = value
			} else {
				t.Values = append(t.Values, tag)
			}
		}
	}
	return t
}

func appendTag(t reflect.StructTag, s string) reflect.StructTag {
	ts := t.Get(ndrNameSpace)
	ts = ndrNameSpace + ":\"" + ts + "," + s + "\""
	return reflect.StructTag(ts)
}

func (t *tags) StructTag() reflect.StructTag {
	mv := t.Values
	for key, val := range t.Map {
		mv = append(mv, key+":"+val)
	}
	s := ndrNameSpace + ":" + `"` + strings.Join(mv, ",") + `"`
	return reflect.StructTag(s)
}

func (t *tags) HasValue(s string) bool {
	return slices.Contains(t.Values, s)
}

func (t *tags) delete(s string) {
	for i, x := range t.Values {
		if x == s {
			t.Values = append(t.Values[:i], t.Values[i+1:]...)
		}
	}
	delete(t.Map, s)
}
