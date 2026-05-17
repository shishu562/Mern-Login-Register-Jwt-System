import jwt from 'jsonwebtoken';

const userAuth = (req, res, next) => {

    const { token } = req.cookies;

    if (!token) {
        return res.json({
            success: false,
            message: "Unauthorized Login Again"
        });
    }

    try {

        const tokenDecode = jwt.verify(
            token,
            process.env.JWT_SECRET
        );

        // Create req.body if undefined
        if (!req.body) {
            req.body = {};
        }

        // req.body.userId = tokenDecode.id;
        req.userId = tokenDecode.id;

        next();

    } catch (error) {
        return res.json({
            success: false,
            message: error.message
        });
    }
}

export default userAuth;