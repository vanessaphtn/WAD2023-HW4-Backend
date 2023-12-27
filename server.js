const express = require('express');
const pool = require('./database');
const cors = require('cors');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');

const port = process.env.PORT || 3000;

const app = express();

app.use(cors({ origin: 'http://localhost:8080', credentials: true }));
// We need to include "credentials: true" to allow cookies to be represented  
// Also "credentials: 'include'" need to be added in Fetch API in the Vue.js App

app.use(express.json()); // Parses incoming requests with JSON payloads and is based on body-parser.
app.use(cookieParser()); // Parse Cookie header and populate req.cookies with an object keyed by the cookie names.

const secret = "gdgdhdbcb770785rgdzqws"; // use a stronger secret
const maxAge = 60 * 60; //unlike cookies, the expiresIn in jwt token is calculated by seconds not milliseconds

const generateJWT = (id) => {
    return jwt.sign({ id }, secret, { expiresIn: maxAge })
        //jwt.sign(payload, secret, [options, callback]), and it returns the JWT as string
}

app.listen(port, () => {
    console.log("Server is listening to port " + port)
});


// is used to check whether a user is authinticated
app.get('/auth/authenticate', async(req, res) => {
    console.log('authentication request has been arrived');
    const token = req.cookies.jwt; // assign the token named jwt to the token const
    //console.log("token " + token);
    let authenticated = false; // a user is not authenticated until proven the opposite
    try {
        if (token) { //checks if the token exists
            //jwt.verify(token, secretOrPublicKey, [options, callback]) verify a token
            await jwt.verify(token, secret, (err) => { //token exists, now we try to verify it
                if (err) { // not verified, redirect to login page
                    console.log(err.message);
                    console.log('token is not verified');
                    res.send({ "authenticated": authenticated }); // authenticated = false
                } else { // token exists and it is verified 
                    console.log('author is authinticated');
                    authenticated = true;
                    res.send({ "authenticated": authenticated }); // authenticated = true
                }
            })
        } else { //applies when the token does not exist
            console.log('author is not authinticated');
            res.send({ "authenticated": authenticated }); // authenticated = false
        }
    } catch (err) {
        console.error(err.message);
        res.status(400).send(err.message);
    }
});

// signup a user
app.post('/auth/signup', async(req, res) => {
    try {
        console.log("a signup request has arrived");
        //console.log(req.body);
        const { email, password } = req.body;

        const salt = await bcrypt.genSalt(); //  generates the salt, i.e., a random string
        const bcryptPassword = await bcrypt.hash(password, salt) // hash the password and the salt 
        const authUser = await pool.query( // insert the user and the hashed password into the database
            "INSERT INTO users(email, password) values ($1, $2) RETURNING*", [email, bcryptPassword]
        );
        console.log(authUser.rows[0].id);
        const token = await generateJWT(authUser.rows[0].id); // generates a JWT by taking the user id as an input (payload)
        //console.log(token);
        //res.cookie("isAuthorized", true, { maxAge: 1000 * 60, httpOnly: true });
        //res.cookie('jwt', token, { maxAge: 6000000, httpOnly: true });
        res
            .status(201)
            .cookie('jwt', token, { maxAge: 6000000, httpOnly: true })
            .json({ user_id: authUser.rows[0].id })
            .send;
    } catch (err) {
        console.error(err.message);
        res.status(400).send(err.message);
    }
});

app.post('/auth/login', async(req, res) => {
    try {
        console.log("a login request has arrived");
        const { email, password } = req.body;
        const user = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
        if (user.rows.length === 0) return res.status(401).json({ error: "User is not registered" });

        /* 
        To authenticate users, you will need to compare the password they provide with the one in the database. 
        bcrypt.compare() accepts the plain text password and the hash that you stored, along with a callback function. 
        That callback supplies an object containing any errors that occurred, and the overall result from the comparison. 
        If the password matches the hash, the result is true.

        bcrypt.compare method takes the first argument as a plain text and the second argument as a hash password. 
        If both are equal then it returns true else returns false.
        */

        //Checking if the password is correct
        const validPassword = await bcrypt.compare(password, user.rows[0].password);
        //console.log("validPassword:" + validPassword);
        if (!validPassword) return res.status(401).json({ error: "Incorrect password" });

        const token = await generateJWT(user.rows[0].id);
        res
            .status(201)
            .cookie('jwt', token, { maxAge: 6000000, httpOnly: true })
            .json({ user_id: user.rows[0].id })
            .send;
    } catch (error) {
        res.status(401).json({ error: error.message });
    }
});

//logout a user = deletes the jwt
app.get('/auth/logout', (req, res) => {
    console.log('delete jwt request arrived');
    res.status(202).clearCookie('jwt').json({ "Msg": "cookie cleared" }).send
});

// Add a new post
app.post('/posts', async(req, res) => {
    try {
        console.log("A request to add a new post has arrived");
        const { body, date } = req.body;

        // Get the user id from the JWT
        const token = req.cookies.jwt;
        const decodedToken = jwt.verify(token, secret);
        const userId = decodedToken.id;

        const newPost = await pool.query(
            "INSERT INTO posts(body, date, user_id) values ($1, $2, $3) RETURNING*", [body, date, userId]
        );
        console.log(newPost.rows[0].id);

        res.status(201).json({ post_id: newPost.rows[0].id });
    } catch (err) {
        console.error(err.message);
        res.status(400).send(err.message);
    }
});

// Get all posts
app.get('/posts', async(req, res) => {
    try {
        console.log("A request to get all posts has arrived");

        // Get the user id from the JWT
        const token = req.cookies.jwt;
        const decodedToken = jwt.verify(token, secret);
        const userId = decodedToken.id;

        const posts = await pool.query(
            "SELECT * FROM posts"
        );
        console.log(posts.rows);

        res.status(200).json(posts.rows);
    } catch (err) {
        console.error(err.message);
        res.status(400).send(err.message);
    }
});

app.delete('/posts', async(req,res) => {
    try {
        console.log("Delete all post request has arrived")

        const deletepost = await pool.query(
            "DELETE FROM posts"
        );
        res.json(deletepost);
    } catch (err){
        console.error(err.message);
    }
});
app.put('/posts/:id', async(req, res) => {
    try {
        console.log("A request to update a post has arrived");

        const { id } = req.params;
        const { body } = req.body;

        const updatePost = await pool.query(
            "UPDATE posts SET body = $1 WHERE id = $2",
            [body, id]
        );
        console.log(updatePost);
        res.json(updatePost);
    } catch (err) {
        console.error(err.message);
    }
});

app.delete('/posts/:postId', async (req, res) => {
    try {
        console.log("Delete a post request has arrived");

        const { postId } = req.params;

        // Get the user id from the JWT
        const token = req.cookies.jwt;
        const decodedToken = jwt.verify(token, secret);
        const userId = decodedToken.id;

        // Check if the post belongs to the authenticated user
        const post = await pool.query("SELECT * FROM posts WHERE id = $1 AND user_id = $2", [postId, userId]);

        if (post.rows.length === 0) {
            // If post does not belong to the user or does not exist, return an error
            return res.status(403).json({ error: "Unauthorized action" });
        }

        const deletepost = await pool.query(
            "DELETE FROM posts WHERE id = $1",
            [postId]
        );

        res.json(deletepost);
    } catch (err) {
        console.error(err.message);
        res.status(500).send(err.message);
    }
});
