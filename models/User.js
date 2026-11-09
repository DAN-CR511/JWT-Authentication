const mongoose = require('mongoose');
const { isEmail } = require('validator');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
    email: {
       type: String,
       required: [true, 'Please enter an email'],
       unique: true,
       lowercase: true,
       validate: [isEmail, 'Please enter a valid email']
    },
    password: {
        type: String,
        required: [true, 'Please enter a password'],
        minlength: [6, 'Minimum password length is 6 characters']
    },    
});

// fire a function before doc saved to db 
userSchema.pre('save', async function () {

    // Only hash the password if it has been modified
    if (!this.isModified('password')) 
        return;

    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);

});

// static method to login user
userSchema.statics.login = async function(email, password) {
    const user = await this.findOne({ email });
    if (user) {
       const auth = await bcrypt.compare(password, user.password);
       if (auth) {
        return user;
       }
       throw Error('incorrect password');
    }
    throw Error('incorrect email');
}

const user = mongoose.model('user', userSchema);

module.exports = user;