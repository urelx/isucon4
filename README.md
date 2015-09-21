# isucon4

```
$ sudo /etc/init.d/supervisord stop
$ git clone git@github.com:urelx/isucon4.git
$ rm -rf env.sh init.sh sql webapp
$ ln -s isucon4/env.sh .
$ ln -s isucon4/init.sh .
$ ln -s isucon4/sql .
$ ln -s isucon4/webapp .
$ sudo /etc/init.d/supervisord start
```
