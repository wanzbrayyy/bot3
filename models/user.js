const mongoose = require('mongoose');
const UserSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  chatId: { type: String, required: true },
  xp: { type: Number, default: 0 },
  level: { type: Number, default: 1 },
  strikeCount: { type: Number, default: 0 },
  muteTier: { type: Number, default: 0 },
  verified: Boolean
});

UserSchema.index({ userId: 1, chatId: 1 }, { unique: true });

module.exports = mongoose.model('User', UserSchema);