import MongoStore from "connect-mongo";
import cors from "cors";
import "dotenv/config";
import express, { Request, Response } from 'express';
import rateLimit from "express-rate-limit";
import session from "express-session";
import helmet from "helmet";
import { connectDB } from "./config/db.js";
import { env } from "./config/env.js";
import AuthRouter from "./routes/Auth.routes.js";
import googleRouter from "./routes/GoogleOAuth.routes.js";
import ThumbnailRouter from "./routes/Thumbnail.routes.js";
import UserRouter from "./routes/User.routes.js";

declare module "express-session" {
    interface SessionData {
        isLoggedIn: boolean,
        userId: string,
        state?: string
    }
}
const app = express();
console.log(">>> BACKEND STARTING...");
console.log(">>> env.CLIENT_URL:", env.CLIENT_URL);
console.log(">>> env.NODE_ENV:", env.NODE_ENV);

connectDB();

app.use((req, res, next) => {
    console.log(`>>> [${new Date().toISOString()}] ${req.method} ${req.url}`);
    console.log(`>>> Origin: ${req.headers.origin}`);
    console.log(`>>> Cookie: ${req.headers.cookie ? 'YES' : 'NO'}`);
    next();
});

// Security middleware
app.use(helmet());

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { message: "Too many requests, please try again later" }
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { message: "Too many login attempts, please try again later" }
});

app.use(limiter);

app.use(cors({
    origin: (origin, callback) => {
        const allowed = [
            "https://thumbnailio.vercel.app"
        ];

        // allow server-to-server / Google redirect (no origin)
        if (!origin) return callback(null, true);

        if (allowed.includes(origin)) {
            return callback(null, true);
        }

        return callback(null, true); //  allow all for now (safe with cookies)
    },
    credentials: true,
}));

app.set("trust proxy", 1);
// console.log(env.NODE_ENV);

app.use(session({
    name: "thumb-io_session",
    secret: env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    proxy: true,

    cookie: {
        maxAge: 1000 * 60 * 60 * 24 * 7,
        httpOnly: true,
        secure: true, // Vercel is always HTTPS
        sameSite: "lax", // Proxy makes it same-domain
        path: "/",
    },

    store: MongoStore.create({
        mongoUrl: env.MONGODB_URI,
        collectionName: "session",
        touchAfter: 24 * 3600,
        crypto: {
            secret: env.SESSION_SECRET
        }
    })
}));

app.use(express.json({ limit: "10kb" }));

app.get("/", (req: Request, res: Response) => {
    res.json({
        message: "Server is working!!!"
    })
})
app.use("/api/v1/auth/login", authLimiter);
app.use("/api/v1/auth/register", authLimiter);

app.use("/api/v1/auth", AuthRouter);
app.use("/api/v1/thumbnail", ThumbnailRouter)
app.use("/api/v1/user", UserRouter)
app.use("/api/v1/googleOAuth", googleRouter)

const port = env.PORT || 3000;

if (env.NODE_ENV !== "production") {
    app.listen(port, () => {
        console.log(`Server is running at :: http://localhost:${port}`);
    })
}

export default app;
// Server restart trigger for env update