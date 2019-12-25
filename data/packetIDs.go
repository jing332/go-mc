package data

// Clientbound packet IDs
const (
	SpawnObject byte = iota //0x00
	SpawnExperienceOrb
	SpawnGlobalEntity
	SpawnMob
	SpawnPainting
	SpawnPlayer
	AnimationClientbound
	Statistics
	BlockBreakAnimation
	UpdateBlockEntity
	BlockAction
	BlockChange
	BossBar
	ServerDifficulty
	TabComplete
	ChatMessageClientbound

	MultiBlockChange //0x10
	ConfirmTransaction
	CloseWindow
	OpenWindow
	WindowItems
	WindowProperty
	SetSlot
	SetCooldown
	PluginMessageClientbound
	NamedSoundEffect
	DisconnectPlay
	EntityStatus
	Explosion
	UnloadChunk
	ChangeGameState
	KeepAliveClientbound

	ChunkData //0x20
	Effect
	Particle
	JoinGame
	Map
	EntityRelativeMove
	EntityLookAndRelativeMove
	EntityLook
	Entity
	VehicleMoveClientbound
	OpenSignEditor
	PlayerAbilitiesClientbound
	CombatEvent
	PlayerListItem
	PlayerPositionAndLookClientbound
	UseBed

	DestroyEntities //0x30
	RemoveEntityEffect
	ResourcePackSend
	Respawn
	EntityHeadLook
	WorldBorder
	Camera
	HeldItemChangeClientbound
	DisplayScoreboard
	EntityMetadata
	AttachEntity
	EntityVelocity
	EntityEquipment
	SetExperience
	UpdateHealth
	ScoreboardObjective

	SetPassengers //0x40
	Teams
	UpdateScore
	SpawnPosition
	TimeUpdate
	Title
	SoundEffect
	PlayerListHeaderAndFooter
	CollectItem
	EntityTeleport
	EntityProperties
	EntityEffect
)

// Serverbound packet IDs
const (
	TeleportConfirm byte = iota //0x00
	TabCompleteServerbound
	ChatMessageServerbound
	ClientStatus
	ClientSettings
	ConfirmTransactionServerbound
	EnchantItem
	ClickWindow
	CloseWindowServerbound
	PluginMessageServerbound
	UseEntity
	KeepAliveServerbound
	PlayerPosition
	PlayerPositionAndLookServerbound
	PlayerLook
	Player

	VehicleMoveServerbound //0x10
	SteerBoat
	PlayerAbilitiesServerbound
	PlayerDigging
	EntityAction
	SteerVehicle
	ResourcePackStatus
	HeldItemChangeServerbound
	CreativeInventoryAction
	UpdateSign
	AnimationServerbound
	Spectate
	PlayerBlockPlacement
	UseItem
)
