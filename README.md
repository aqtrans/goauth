[![build status](https://git.jba.io/go/auth/badges/master/build.svg)](https://git.jba.io/go/auth/commits/master)
[![coverage report](https://git.jba.io/go/auth/badges/master/coverage.svg)](https://git.jba.io/go/auth/commits/master)

**Note: This library depends on the 'context' library integrated into stdlib in Go 1.7**

This is a library I wrote when I found existing http auth libraries lacking in one area or another.  
Not entirely documented yet, but I've pounded most of the kinks out and felt it was about time to share.  

# Currently handles the following:  
## User Auth:  
   - User sign-up, stored in a Boltdb named auth.db  
   - User authentication against Boltdb  
       - Cookie-powered  
       - With go1.7/context to help pass around the user info  
   - AdminUser specified is made an Admin, so only one admin  
   - Boltdb powered, using a Users buckets  
   - Success/failure is delivered via a redirect and a "flash" message  

## XSRF:  
   - Cross-site Request Forgery protection, using the same concept I use for auth functions above  
