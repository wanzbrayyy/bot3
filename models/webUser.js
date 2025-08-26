const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const WebUserSchema = new mongoose.Schema({
    telegramId: { type: String, required: true, unique: true },
    telegramUsername: { type: String, required: true },
    password: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

WebUserSchema.pre('save', async function(next) {
    if (!this.isModified('password')) {
        return next();
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
});

WebUserSchema.methods.matchPassword = async function(enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

module.exports = mongoose.model('WebUser', WebUserSchema);