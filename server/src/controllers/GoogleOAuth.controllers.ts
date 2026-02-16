import crypto from 'crypto';
import { Request, Response } from "express";
import { google } from 'googleapis';
import { env } from '../config/env.js';
import oauth2Client from '../config/googleOAuth.js';
import User from '../models/User.models.js';

const scopes = [
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "openid"
];

const CLIENT_URL = env.CLIENT_URL;
const STATE_SECRET = env.SESSION_SECRET; // reuse session secret for HMAC signing

// Create a signed state token (no session dependency)
function createSignedState(): string {
    const timestamp = Date.now().toString();
    const nonce = crypto.randomBytes(16).toString('hex');
    const payload = `${timestamp}.${nonce}`;
    const signature = crypto.createHmac('sha256', STATE_SECRET).update(payload).digest('hex');
    return `${payload}.${signature}`;
}

// Verify the signed state token
function verifySignedState(state: string): boolean {
    const parts = state.split('.');
    if (parts.length !== 3) return false;
    const [timestamp, nonce, signature] = parts;

    // Check if state is expired (10 minute window)
    const age = Date.now() - parseInt(timestamp);
    if (age > 10 * 60 * 1000) return false;

    // Verify HMAC signature
    const payload = `${timestamp}.${nonce}`;
    const expectedSignature = crypto.createHmac('sha256', STATE_SECRET).update(payload).digest('hex');
    return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature));
}

export const googleLogin = async (req: Request, res: Response) => {
    try {
        const state = createSignedState();
        console.log(">>> googleLogin - Using Redirect URL:", env.GOOGLE_OAUTH_REDIRECT_URL);

        const authorizationUrl = oauth2Client.generateAuthUrl({
            access_type: "online",
            scope: scopes,
            state: state
        });

        res.redirect(authorizationUrl);
    } catch (error) {
        console.error('Google OAuth Login Error:', error);
        return res.redirect(`${CLIENT_URL}/login?error=oauth_failed`);
    }
}

export const googleCallback = async (req: Request, res: Response) => {
    try {
        const { code, state, error } = req.query;

        if (error) {
            console.error('Google OAuth Error:', error);
            return res.redirect(`${CLIENT_URL}/login?error=oauth_denied`);
        }

        // Verify the signed state token (no session needed)
        if (!state || !verifySignedState(state as string)) {
            console.error('State verification failed');
            return res.redirect(`${CLIENT_URL}/login?error=invalid_state`);
        }

        const { tokens } = await oauth2Client.getToken(code as string);
        oauth2Client.setCredentials(tokens);

        const oauth2 = google.oauth2({ version: 'v2', auth: oauth2Client });
        const { data: googleUser } = await oauth2.userinfo.get();

        if (!googleUser.email) {
            return res.redirect(`${CLIENT_URL}/login?error=no_email`);
        }

        let user = await User.findOne({ email: googleUser.email });

        if (!user) {
            user = new User({
                name: googleUser.name || googleUser.email.split('@')[0],
                email: googleUser.email,
                password: undefined,
                credits: 20,
            });
            await user.save();
        }

        req.session.isLoggedIn = true;
        req.session.userId = user._id.toString();
        console.log(">>> googleCallback - Setting session for userId:", req.session.userId);

        // Explicitly save session before redirecting
        req.session.save((err) => {
            if (err) {
                console.error('>>> googleCallback - Session save error:', err);
                return res.redirect(`${CLIENT_URL}/login?error=session_error`);
            }
            console.log(">>> googleCallback - Session saved successfully. Redirecting to:", CLIENT_URL);
            return res.redirect(CLIENT_URL as string);
        });

    } catch (error: any) {
        console.error('Google OAuth Callback Error:', error);
        return res.redirect(`${CLIENT_URL}/login?error=oauth_failed`);
    }
}