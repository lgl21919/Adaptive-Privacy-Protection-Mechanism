package crypto

import (
	"encoding/json"
	"fmt"
	"math/big"
	"time"
)

// SerializableECPoint 可序列化的椭圆曲线点
type SerializableECPoint struct {
	X string `json:"x"`
	Y string `json:"y"`
}

// SerializableReEncryptionKey 可序列化的重加密密钥
type SerializableReEncryptionKey struct {
	Alpha     string              `json:"alpha"`
	Beta      SerializableECPoint `json:"beta"`
	FromID    string              `json:"from_id"`
	ToID      string              `json:"to_id"`
	CreatedAt time.Time           `json:"created_at"`
	ExpiresAt time.Time           `json:"expires_at"`
	MAC       []byte              `json:"mac"`
}

// SerializableCiphertext 可序列化的密文
type SerializableCiphertext struct {
	C1        SerializableECPoint `json:"c1"`
	C2        []byte              `json:"c2"`
	IV        []byte              `json:"iv"`
	Level     int                 `json:"level"`
	Timestamp time.Time           `json:"timestamp"`
	MAC       []byte              `json:"mac"`
}

// SerializableReEncryptedCiphertext 可序列化的重加密密文
type SerializableReEncryptedCiphertext struct {
	Ciphertext     SerializableCiphertext `json:"ciphertext"`
	OriginalC1     SerializableECPoint    `json:"original_c1"`        // 新增
	OriginalFromID string                 `json:"original_from_id"`
	ReEncryptedBy  string                 `json:"re_encrypted_by"`
	Proof          []byte                 `json:"proof"`
}

// ToSerializable 将ECPoint转换为可序列化格式
func (p *ECPoint) ToSerializable() SerializableECPoint {
	return SerializableECPoint{
		X: p.X.String(),
		Y: p.Y.String(),
	}
}

// FromSerializable 从可序列化格式创建ECPoint
func (p *SerializableECPoint) FromSerializable() (*ECPoint, error) {
	x, ok := new(big.Int).SetString(p.X, 10)
	if !ok {
		return nil, fmt.Errorf("无效的X坐标: %s", p.X)
	}

	y, ok := new(big.Int).SetString(p.Y, 10)
	if !ok {
		return nil, fmt.Errorf("无效的Y坐标: %s", p.Y)
	}

	return &ECPoint{X: x, Y: y}, nil
}

// ToSerializable 将重加密密钥转换为可序列化格式
func (rk *ReEncryptionKey) ToSerializable() SerializableReEncryptionKey {
	return SerializableReEncryptionKey{
		Alpha:     rk.Alpha.String(),
		Beta:      rk.Beta.ToSerializable(),
		FromID:    rk.FromID,
		ToID:      rk.ToID,
		CreatedAt: rk.CreatedAt,
		ExpiresAt: rk.ExpiresAt,
		MAC:       rk.MAC,
	}
}

// FromSerializable 从可序列化格式创建重加密密钥
func (srk *SerializableReEncryptionKey) FromSerializable() (*ReEncryptionKey, error) {
	alpha, ok := new(big.Int).SetString(srk.Alpha, 10)
	if !ok {
		return nil, fmt.Errorf("无效的Alpha值: %s", srk.Alpha)
	}

	beta, err := srk.Beta.FromSerializable()
	if err != nil {
		return nil, fmt.Errorf("解析Beta失败: %w", err)
	}

	return &ReEncryptionKey{
		Alpha:     alpha,
		Beta:      beta,
		FromID:    srk.FromID,
		ToID:      srk.ToID,
		CreatedAt: srk.CreatedAt,
		ExpiresAt: srk.ExpiresAt,
		MAC:       srk.MAC,
	}, nil
}

// ToSerializable 将密文转换为可序列化格式
func (ct *Ciphertext) ToSerializable() SerializableCiphertext {
	return SerializableCiphertext{
		C1:        ct.C1.ToSerializable(),
		C2:        ct.C2,
		IV:        ct.IV,
		Level:     ct.Level,
		Timestamp: ct.Timestamp,
		MAC:       ct.MAC,
	}
}

// FromSerializable 从可序列化格式创建密文
func (sct *SerializableCiphertext) FromSerializable() (*Ciphertext, error) {
	c1, err := sct.C1.FromSerializable()
	if err != nil {
		return nil, fmt.Errorf("解析C1失败: %w", err)
	}

	return &Ciphertext{
		C1:        c1,
		C2:        sct.C2,
		IV:        sct.IV,
		Level:     sct.Level,
		Timestamp: sct.Timestamp,
		MAC:       sct.MAC,
	}, nil
}

// ToSerializable 将重加密密文转换为可序列化格式
func (rect *ReEncryptedCiphertext) ToSerializable() SerializableReEncryptedCiphertext {
    return SerializableReEncryptedCiphertext{
        Ciphertext:     rect.Ciphertext.ToSerializable(),
        OriginalC1:     rect.OriginalC1.ToSerializable(),
        OriginalFromID: rect.OriginalFromID,
        ReEncryptedBy:  rect.ReEncryptedBy,
        Proof:          rect.Proof,
    }
}

// FromSerializable 从可序列化格式创建重加密密文
func (srect *SerializableReEncryptedCiphertext) FromSerializable() (*ReEncryptedCiphertext, error) {
    // ... existing code ...
    ct, err := srect.Ciphertext.FromSerializable()
    if err != nil {
        return nil, err
    }
    origC1, err := srect.OriginalC1.FromSerializable()
    if err != nil {
        return nil, err
    }

    return &ReEncryptedCiphertext{
        Ciphertext:      ct,
        OriginalC1:      origC1,
        OriginalFromID:  srect.OriginalFromID,
        ReEncryptedBy:   srect.ReEncryptedBy,
        Proof:           srect.Proof,
    }, nil
    // ... existing code ...
}

// MarshalJSON 实现JSON序列化
func (rk *ReEncryptionKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(rk.ToSerializable())
}

// UnmarshalJSON 实现JSON反序列化
func (rk *ReEncryptionKey) UnmarshalJSON(data []byte) error {
	var srk SerializableReEncryptionKey
	if err := json.Unmarshal(data, &srk); err != nil {
		return err
	}

	parsed, err := srk.FromSerializable()
	if err != nil {
		return err
	}

	*rk = *parsed
	return nil
}

// MarshalJSON 实现JSON序列化
func (ct *Ciphertext) MarshalJSON() ([]byte, error) {
	return json.Marshal(ct.ToSerializable())
}

// UnmarshalJSON 实现JSON反序列化
func (ct *Ciphertext) UnmarshalJSON(data []byte) error {
	var sct SerializableCiphertext
	if err := json.Unmarshal(data, &sct); err != nil {
		return err
	}

	parsed, err := sct.FromSerializable()
	if err != nil {
		return err
	}

	*ct = *parsed
	return nil
}

// MarshalJSON 实现JSON序列化
func (rect *ReEncryptedCiphertext) MarshalJSON() ([]byte, error) {
	return json.Marshal(rect.ToSerializable())
}

// UnmarshalJSON 实现JSON反序列化
func (rect *ReEncryptedCiphertext) UnmarshalJSON(data []byte) error {
	var srect SerializableReEncryptedCiphertext
	if err := json.Unmarshal(data, &srect); err != nil {
		return err
	}

	parsed, err := srect.FromSerializable()
	if err != nil {
		return err
	}

	*rect = *parsed
	return nil
}

// SerializeCiphertext 序列化密文为字节数组
func SerializeCiphertext(ct *Ciphertext) ([]byte, error) {
	return json.Marshal(ct)
}

// DeserializeCiphertext 从字节数组反序列化密文
func DeserializeCiphertext(data []byte) (*Ciphertext, error) {
	var ct Ciphertext
	if err := json.Unmarshal(data, &ct); err != nil {
		return nil, fmt.Errorf("反序列化密文失败: %w", err)
	}
	return &ct, nil
}

// SerializeReEncryptionKey 序列化重加密密钥为字节数组
func SerializeReEncryptionKey(rk *ReEncryptionKey) ([]byte, error) {
	return json.Marshal(rk)
}

// DeserializeReEncryptionKey 从字节数组反序列化重加密密钥
func DeserializeReEncryptionKey(data []byte) (*ReEncryptionKey, error) {
	var rk ReEncryptionKey
	if err := json.Unmarshal(data, &rk); err != nil {
		return nil, fmt.Errorf("反序列化重加密密钥失败: %w", err)
	}
	return &rk, nil
}

// SerializeReEncryptedCiphertext 序列化重加密密文为字节数组
func SerializeReEncryptedCiphertext(rect *ReEncryptedCiphertext) ([]byte, error) {
	return json.Marshal(rect)
}

// DeserializeReEncryptedCiphertext 从字节数组反序列化重加密密文
func DeserializeReEncryptedCiphertext(data []byte) (*ReEncryptedCiphertext, error) {
	var rect ReEncryptedCiphertext
	if err := json.Unmarshal(data, &rect); err != nil {
		return nil, fmt.Errorf("反序列化重加密密文失败: %w", err)
	}
	return &rect, nil
}

// ValidateCiphertext 验证密文结构的完整性
func ValidateCiphertext(ct *Ciphertext) error {
	if ct.C1 == nil {
		return fmt.Errorf("密文C1不能为空")
	}
	if ct.C1.X == nil || ct.C1.Y == nil {
		return fmt.Errorf("椭圆曲线点坐标不能为空")
	}
	if len(ct.C2) == 0 {
		return fmt.Errorf("密文C2不能为空")
	}
	if len(ct.IV) == 0 {
		return fmt.Errorf("初始化向量不能为空")
	}
	if len(ct.MAC) == 0 {
		return fmt.Errorf("消息认证码不能为空")
	}
	if ct.Level < 1 || ct.Level > 2 {
		return fmt.Errorf("密文级别必须为1或2")
	}
	return nil
}

// ValidateReEncryptionKey 验证重加密密钥结构的完整性
func ValidateReEncryptionKey(rk *ReEncryptionKey) error {
	if rk.Alpha == nil {
		return fmt.Errorf("重加密密钥Alpha不能为空")
	}
	if rk.Beta == nil {
		return fmt.Errorf("重加密密钥Beta不能为空")
	}
	if rk.Beta.X == nil || rk.Beta.Y == nil {
		return fmt.Errorf("Beta椭圆曲线点坐标不能为空")
	}
	if rk.FromID == "" || rk.ToID == "" {
		return fmt.Errorf("用户ID不能为空")
	}
	if len(rk.MAC) == 0 {
		return fmt.Errorf("消息认证码不能为空")
	}
	if rk.ExpiresAt.Before(rk.CreatedAt) {
		return fmt.Errorf("过期时间不能早于创建时间")
	}
	return nil
}

// CopyECPoint 复制椭圆曲线点
func CopyECPoint(point *ECPoint) *ECPoint {
	if point == nil {
		return nil
	}
	return &ECPoint{
		X: new(big.Int).Set(point.X),
		Y: new(big.Int).Set(point.Y),
	}
}

// CopyCiphertext 深度复制密文
func CopyCiphertext(ct *Ciphertext) *Ciphertext {
	if ct == nil {
		return nil
	}

	newCt := &Ciphertext{
		C1:        CopyECPoint(ct.C1),
		Level:     ct.Level,
		Timestamp: ct.Timestamp,
	}

	// 复制字节切片
	if ct.C2 != nil {
		newCt.C2 = make([]byte, len(ct.C2))
		copy(newCt.C2, ct.C2)
	}

	if ct.IV != nil {
		newCt.IV = make([]byte, len(ct.IV))
		copy(newCt.IV, ct.IV)
	}

	if ct.MAC != nil {
		newCt.MAC = make([]byte, len(ct.MAC))
		copy(newCt.MAC, ct.MAC)
	}

	return newCt
}

// CopyReEncryptionKey 深度复制重加密密钥
func CopyReEncryptionKey(rk *ReEncryptionKey) *ReEncryptionKey {
	if rk == nil {
		return nil
	}

	newRk := &ReEncryptionKey{
		Alpha:     new(big.Int).Set(rk.Alpha),
		Beta:      CopyECPoint(rk.Beta),
		FromID:    rk.FromID,
		ToID:      rk.ToID,
		CreatedAt: rk.CreatedAt,
		ExpiresAt: rk.ExpiresAt,
	}

	if rk.MAC != nil {
		newRk.MAC = make([]byte, len(rk.MAC))
		copy(newRk.MAC, rk.MAC)
	}

	return newRk
}