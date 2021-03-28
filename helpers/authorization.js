const jwt = require('jsonwebtoken');

async function authenticate(req, res, next) {
    try {
        console.log("---------middleWare----------------------")
        if (req.headers.authorization != undefined) {
            await jwt.verify(
                req.headers.authorization,
                process.env.JWT_KEY, (err, decode) => {
                    if (err) res.status(500)
                    if (decode != undefined) {
                        req.role = decode.role;
                        console.log(decode)
                        next();
                    } else {
                        res.status(401).json({ message: "Invalid token" })
                    }
                });
        } else {
            res.status(401).json({ message: "No token in headers" })
        }
    } catch {
        console.log("error")
        res.status(401).json({ message: "error" })
    }
}

function isValidRole(role) {
    return function( req, res, next){
        if(req.role && req.role == role){
            next()
        } else {
            res.send(403)
        }
    }
}


module.exports = { authenticate, isValidRole };