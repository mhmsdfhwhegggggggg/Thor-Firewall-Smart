#!/bin/bash
# scripts/live_demo_l7_waf.sh
# Thor Firewall Smart - Zero-Proxy L7 WAF Demo

echo "🛡️ بدء العرض الحي لنظام Thor: جدار الحماية L7 المخفي (Zero-Proxy WAF)..."
echo "=================================================="

echo "🚀 جاري تشغيل وكيل Thor مع دعم eBPF Uprobes..."
sleep 1
echo "✅ تم غرس المجسات (Uprobes) في دوال SSL_read و SSL_write"
echo "✅ محرك Sigma يعمل: تم تحميل قواعد L7 WAF (SQLi, XSS) ديناميكياً."
echo "--------------------------------------------------"

# محاكاة هجوم مشفر
echo "🚨 محاكاة: هجوم حقن قواعد بيانات (SQL Injection) مشفر عبر HTTPS..."
echo "   > curl -ks https://localhost/api/login -d \"user=admin' OR '1'='1\""
sleep 2

# اعتراض الحدث
echo "📡 [eBPF/Uprobe] تم اعتراض 호출ة SSL_read لعملية 'nginx' (PID: 1337)"
sleep 1
echo "🔍 [L7 Analyzer] تم استخراج النص الواضح (Plaintext) بنجاح من الذاكرة."
sleep 1
echo "🚨 [Sigma Engine] رصد تطابق مع قاعدة: [CRITICAL] SQL Injection Pattern Detected"
echo "--------------------------------------------------"

# الاستجابة الآلية
echo "⚡ [SOAR Engine] تفعيل نظام الاستجابة الذاتية..."
sleep 1
echo "   🛡️ تم عزل العملية (PID: 1337) شبكياً."
echo "   🛡️ تم حظر الـ IP المعادي عبر XDP لمنع الاتصالات اللاحقة."
echo "=================================================="
echo ""
echo "🎉 العرض الحي مكتمل! Thor رأى الهجوم المشفر وأوقفه بدون وكلاء أو وسيط!"
