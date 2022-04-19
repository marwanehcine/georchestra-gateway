
# Configuration properties

## Configuration object model

```mermaid
classDiagram
  GatewayConfigProperties *-- HeaderMappings : defaultHeaders
  GatewayConfigProperties *-- "0..*" RoleBasedAccessRule : globalAccessRules
  GatewayConfigProperties *-- "0..*" Service
  Service *-- HeaderMappings : headers
  Service *-- "0..*" RoleBasedAccessRule : accessRules
  class GatewayConfigProperties{
    Map<String, Service> services
  }
  class HeaderMappings{
    boolean proxy
    boolean username
    boolean roles
    boolean org
    boolean orgname
    boolean email
    boolean firstname
    boolean lastname
    boolean tel
    boolean jsonUser
    boolean jsonOrganization
  }
  class RoleBasedAccessRule{
    List~String~ interceptUrl
    boolean anonymous
    List~String~ allowedRoles
  }
  class Service{
    URL target
  }
```

## Example YAML configuration

```yaml
georchestra:
  gateway:
    default-headers:
      proxy: true
      username: true
      roles: true
      org: true
      orgname: true
    global-access-rules:
    - intercept-url: /**
      anonymous: true
    services:
      analytics:
        target: http://analytics:8080/analytics/
        access-rules:
        - intercept-url: /analytics/**
          allowed-roles: SUPERUSER, ORGADMIN
      atlas: 
        target: http://atlas:8080/atlas/
      console: 
        target: http://console:8080/console/
        access-rules:
        - intercept-url:
          - /console/public/**
          - /console/manager/public/**
          anonymous: true
        - intercept-url:
          - /console/private/**
          - /console/manager/**
          allowed-roles: SUPERUSER, ORGADMIN
```