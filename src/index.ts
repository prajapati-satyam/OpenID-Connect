import express  from "express";
import type { Express, Request, Response } from "express";
import 'dotenv/config';
import { drizzle } from 'drizzle-orm/node-postgres';
import path from "path";
import { readFileSync } from "fs";
import jose from "node-jose"
import { usersTable } from "./db/schema";
import { eq } from "drizzle-orm";
import crypto from 'crypto';
import jwt from "jsonwebtoken";

const db = drizzle(process.env.DATABASE_URL!);


type JWTCliams =  {
        iss: string,
        sub: string,
        email: string,
        exp: number,
        given_name: string | "",
        family_name: string |  "" | undefined,
        name: string
}

const port:number = 3000

const PRIVATE_KEY = readFileSync(path.resolve('./cert/private-key.pem'))
const PUBLIC_KEY = readFileSync(path.resolve('./cert/public-key.pub'))

const app:Express = express();

app.use(express.json())
app.use(express.static(path.resolve('public')))

app.get('/', (req: Request,res:Response) => {
   res.status(200).json({message: "Hello world"})
})

app.get('/.well-known/openid-configuration', (req:Request,res:Response)=> {
    const url = `http://localhost:${port}`
    const obj = {
       issuer: url,
       authorization_endpoint: `${url}/o/authenticate`,
       userinfo_endpoint: `${url}/o/userinfo`,
       jwks_uri: `${url}/.well-know.jwks.json`
    }
    return res.status(200).send(obj)
})

app.get('/.well-know.jwks.json', async (req:Request, res:Response) => {
    const key = await jose.JWK.asKey(PUBLIC_KEY, "pem")
    return res.status(200).json({keys: [key.toJSON()]})
})

app.get('/o/authenticate', (req:Request,res:Response) => {
    res.sendFile(path.resolve("public", "signin.html"))
})

app.post('/o/authenthicate/signup', async (req:Request,res:Response) => {
    const {first_name, last_name, email, password} = req.body;
    if (!first_name || !email || !password) {
        res.status(400).json({
            message: "first_name, mail and password are mandatory"
        })
    }
    try {
    const [isUserExist] = await db.select().from(usersTable).where(eq(usersTable.email, email)).limit(1);
    if (isUserExist) {
        return res.status(400).json({
            message: "User Already Exists"
        })
    }
    const salt = crypto.randomBytes(16).toString("hex");
    const hash_password = crypto.createHash("sha256").update(password + salt).digest('hex');
    const save_user = await db.insert(usersTable).values({
        first_name,
        last_name: last_name ?? "",
        email,
        password: hash_password,
        salt
    });
    return res.status(200).json({
        message: "user created"
    })
  } catch(err) {
    console.log("Error in user signup : ", err)
    return res.status(400).json({
        message: "Something went wrong",
        error: err
    })
  }
})

app.post('/o/authenthicate/signin', async (req:Request,res:Response)=> {
    const {email, password} = req.body
    if (!email || !password) {
      return res.status(400).json({
        message: "email id and password is required for login"
      })
    }
    const [isUserExist] = await db.select().from(usersTable).where(eq(usersTable.email, email)).limit(1);
    if(!isUserExist || !isUserExist.email || !isUserExist.password) {
        return res.status(400).json({
            message: "Invaid Email or Password"
        })
    }
    const hash_password = crypto.createHash("sha256").update(password+isUserExist.salt).digest("hex");
    if (hash_password !== isUserExist.password){
        return res.status(400).json({
            message: "Invaid Email or Password"
        })
    }
    const issuer = `http://localhost:${port}`
    const now = Math.floor(Date.now() / 1000)
    const claims:JWTCliams = {
        iss: issuer,
        sub: isUserExist.id,
        email: isUserExist.email,
        exp: now + 3600,
        given_name: String(isUserExist.first_name ?? ""),
        family_name: String(isUserExist.last_name ?? undefined),
        name: isUserExist.first_name+isUserExist.last_name
    }
    const token = jwt.sign(claims, PRIVATE_KEY, {algorithm: "RS256"})

    return res.status(200).json({token})

})

app.get('/o/userinfo', async (req:Request,res:Response) => {
    const auth_header = req.headers.authorization
    if (!auth_header || !auth_header.startsWith("Bearer ")) {
        return res.status(400).json({
            message: "Auth Header is required"
        })
    }
    const token = auth_header.split(' ')[1];
    if (!token) {
        return res.status(200).json({
            message: "No token provided"
        })
    }
    try {
        const isValid = jwt.verify(token, PUBLIC_KEY, {algorithms: ["RS256"]}) as JWTCliams;
        if (isValid) {
           const [finduser] = await db.select().from(usersTable).where(eq(usersTable.id, isValid.sub)).limit(1);
           if (!finduser || !finduser.email || !finduser.first_name || !finduser.id) {
            console.log("error in user finding in userinfo", finduser)
            return res.status(200).json({message: "Something Went wrong"})
           }
        const obj = {
        sub: finduser.id,
        email: finduser.email,
        given_name: finduser.first_name,
        family_name: finduser.last_name,
        name: finduser.first_name+finduser.last_name
           }
           return res.status(200).json(obj)
        }
    } catch (err) {
        console.log("invalid token")
        return res.json({
            message: "token is invalid"
        })
    }
})

try {
    app.listen(port, () => {console.log(`app listeing on port : ${port}`);
    })

} catch(err) {
    console.log("Unable to start server");
}