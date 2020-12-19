package authsvc

type Middleware func(Service) Service
