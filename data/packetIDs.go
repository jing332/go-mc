package data

// Clientbound packet IDs
const (
	KeepAliveClientbound byte = iota //0x00
	JoinGame
	ChatMessageClientbound
	TimeUpdate
	EntityEquipment
	SpawnPosition
	UpdateHealth
	Respawn
	PlayerPositionAndLookClientbound
	HeldItemChangeClientbound
	UseBed
	Animation
	SpawnPlayer
	CollectItem
	SpawnObject
	SpawnMob

	SpawnPainting //0x10
	SpanExperienceOrb
	EntityVelocity
	DestroyEntities
	Entity
	EntityRelativeMove
	EntityLook
	EntityLookAndRelativeMove
	EntityTeleport
	EntityHeadLook
	EntityStatus
	AttachEntity
	EntityMetadata
	EntityEffect
	RemoveEntityEffect
	SetExperience

	EntityProperties //0x20
	ChunkData
	MultiBlockChange
	BlockChange
	BlockAction
	BlockBreakAnimation
	MapChunkBulk
	Explosion
	Effect
	SoundEffect
	Particle
	ChangeGameState
	SpawnGlobalEntity
	OpenWindow
	CloseWindowClientbound
	SetSlot

	WindowItems //0x30
	WindowProperty
	ConfirmTransaction
	UpdateSignClientbound
	Maps
	UpdateBlockEntity
	SignEditorOpen
	Statistics
	PlayerListItem
	PlayerAbilitiesClientbound
	TabComplete
	ScoreboardObjective
	UpdateScore
	DisplayScoreboard
	Teams
	PluginMessageClientbound
	Disconnect
)

// Serverbound packet IDs
const (
	KeepAliveServerbound byte = iota //0x00
	ChatMessageServerbound
	UseEntity
	Player
	PlayerPosition
	PlayerLook
	PlayerPositionAndLookServerbound
	PlayerDigging
	PlayerBlockPlacement
	HeldItemChangeServerbound
	AnimationServerbound
	EntityAction
	SteerVehicle
	CloseWindowServerbound
	ClickWindow
	ConfirmTransactionServerbound

	CreativeInventoryAction //0x10
	EnchantItem
	UpdateSignServerbound
	PlayerAbilitiesServerbound
	TabCompleteServerbound
	ClientSettings
	ClientStatus
	PluginMessageServerbound
)
