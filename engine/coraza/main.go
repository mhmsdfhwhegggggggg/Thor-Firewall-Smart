package main

import (
    "github.com/corazawaf/coraza/v3"
    "github.com/envoyproxy/envoy/contrib/golang/filters/http/source/go/pkg/api"
    "github.com/envoyproxy/envoy/contrib/golang/filters/http/source/go/pkg/http"
)

type corazaFilter struct {
    waf coraza.WAF
    tx  coraza.Transaction
}

func (f *corazaFilter) DecodeHeaders(header api.RequestHeaderMap, endStream bool) api.StatusType {
    tx := f.waf.NewTransaction()
    defer tx.Close()
    
    // فحص الطلب
    it, err := tx.ProcessRequestHeader(header)
    if err != nil {
        return api.Continue
    }
    
    if it != nil {
        // هجوم مكتشف
        header.Set("X-Thor-Decision", "blocked")
        header.Set("X-Thor-Rule", it.RuleID)
        return api.LocalReply
    }
    
    return api.Continue
}

func main() {
    http.RegisterHttpFilterConfigFactory("thor.waf", func(config interface{}) api.StreamFilterFactory {
        return func(callbacks api.FilterCallbackHandler) api.StreamFilter {
            waf, _ := coraza.NewWAF(coraza.NewWAFConfig().
                WithDirectives("Include @coraza.conf-recommended"))
            
            return &corazaFilter{waf: waf}
        }
    })
}
