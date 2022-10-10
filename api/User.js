const express = require('express');
const router = express.Router();

// mongodb user model
const User = require('./../models/User');

// password handling
const bcyrpt = require('bcrypt');

// sign up
router.post('/signup', (req, res) => {
    let {name, username, password} = req.body;
    name = name.trim();
    username = username.trim();
    password = password.trim();

    if (name == '' || username == '' || password == ''){
        res.json({
            status: "FAILED",
            message: "Empty input fields"
        });
    } else if (!/^[a-zA-z]*$/.test(name)) {
        res.json({
            status: "FAILED",
            message: "Invalid name entered"
        })
    } else if (/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(username)){
        res.json({
            status: "FAILED",
            message: "Invalid username entered"
        })
    } else if (password.length < 4) {
        res.json({
            status: 'FAILED',
            message: 'Password too short'
        })

    } else {
        // check if user already exists
        User.find({username}).then(result => {
            if (result.length){
                // user exists
                res.json({
                    status: 'FAILED',
                    message: 'User already exists'
                })
            } else {
                // create new user

                // password handling
                const saltRouds = 10;
                bcyrpt.hash(password,saltRouds).then(hashedPassword => {
                    const newUser = new User({
                        name,
                        username,
                        password: hashedPassword
                    });

                    newUser.save().then(result => {
                        res.json({
                            status: 'SUCCESS',
                            message: "Sign up completed",
                            data: result,
                        })
                    })
                    .catch(err => {
                        res.json({
                            status: 'FAILED',
                            message: 'Error while saving user account'
                        })
                    })
                })
                .catch(err => {
                    res.json({
                        status: 'FAILED',
                        message: 'Hashing error'
                    })
                })
            }
        }).catch(err => {
            console.log(err);
            res.json({
                status: 'FAILED',
                message: 'Error occured while checking for user'
            })
        })
    }
})

// sign in
router.post('/signin', (req, res) => {
    let {username, password} = req.body;
    username = username.trim();
    password = password.trim();

    if (username == "" || password == "") {
        res.json({
            status: 'FAILED',
            message: 'Empty field'
        });
    } else {
        // check if user exists
        User.find({username})
        .then((data => {
            if (data.length) {
                // user exists

                const hashedPassword = data[0].password;
                bcyrpt.compare(password, hashedPassword).then(result => {
                    if (result) {
                        // pw match
                        res.json({
                            status: 'SUCCESS',
                            message: 'Signed in',
                            data: data
                        })
                    } else {
                        res.json({
                            status: 'FAILED',
                            message: 'Incorrect password'
                        })
                    }
                })
                .catch(err => {
                    res.json({
                    status: 'FAILED',
                    message: 'Error occured while checking for existing user'
                })
                })
            } else {
                res.json({
                    status: 'FAILED',
                    message: 'Invalid credentials entered'
                })
            }
        }))
        .catch(err => {
            res.json({
                status: 'FAILED',
                message: 'An error occured while checking for existing user'
            })
        })
    }
})

module.exports = router;