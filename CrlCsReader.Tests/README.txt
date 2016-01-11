makecert -n "CN=foo.bar" -r -sv foobar.pvk foobar.cer
#Password: foobar
makecert -crl -n "CN=foo.bar" -r -sv foobar.pvk foobar.crl
