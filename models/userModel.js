const mongoose = require('mongoose')
const Schema = mongoose.Schema
const bcrypt = require('bcrypt')
const validator = require('validator')

const userSchema = new Schema({
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    }
})

//static signup method
userSchema.statics.signup = async function(email, password) {    //has to be regular function when using the 'this' keyword

    //validating 
    if(!email || !password){
        throw Error('All fields must be filled')
    }

    if(!validator.isEmail(email)){
        throw Error('Email is not valid')
    }

    if(!validator.isStrongPassword(password)){
        throw Error('Password is not strong enough')
    }

    const emailExists = await this.findOne({ email })   // check if email already exists in db

    if(emailExists){
        throw Error('Email already in use')             //if email already exists throw error
    }

    const salt = await bcrypt.genSalt(10)               //if not start by generating the salt to be added to pw
    const hash = await bcrypt.hash(password, salt)      // hash the pw with salt

    const user = await this.create({email, password: hash})         // add user to the db

    return user
}

//static login method
userSchema.statics.login = async function(email, password){
    if(!email || !password){
        throw Error('All fields must be filled')
    }

    const user = await this.findOne({ email })

    if(!user){
        throw Error('Incorrect email')
    }

    const match = await bcrypt.compare(password, user.password)

    if(!match){
        throw Error('Incorrect password')
    }

    return user

}

module.exports = mongoose.model('User', userSchema)