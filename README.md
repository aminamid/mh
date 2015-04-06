## Usage

```
connection := [<name>=][<protocol>://]<user>[:<password>][@<host>[:<port>]]
connections := connection,connection,....
connections := connection,connection,....
```

```
mh tag1=user1:pass1@host1.com tag2=user1:pass1@host2.com tag3=user1:pass1@host3.com
mh tag1=user1:pass1@host1.com,su://root:root_pw user2:pass2@host2.com,su://root:root_pw
```
