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
	MapData
	Entity
	EntityRelativeMove
	EntityLookAndRelativeMove
	EntityLook
	VehicleMoveClientbound
	OpenSignEditor
	CraftRecipeResponse
	PlayerAbilitiesClientbound
	CombatEvent
	PlayerListItem
	PlayerPositionAndLookClientbound

	UseBed //0x30
	UnlockRecipes
	DestroyEntities
	RemoveEntityEffect
	ResourcePackSend
	Respawn
	EntityHeadLook
	SelectAdvancementTab
	WorldBorder
	Camera
	HeldItemChangeClientbound
	DisplayScoreboard
	EntityMetadata
	AttachEntity
	EntityVelocity
	EntityEquipment

	SetExperience //0x40
	UpdateHealth
	ScoreboardObjective
	SetPassengers
	Teams
	UpdateScore
	SpawnPosition
	TimeUpdate
	Title
	SoundEffect
	PlayerListHeaderAndFooter
	CollectItem
	EntityTeleport
	Advancements
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
	Player
	PlayerPosition
	PlayerPositionAndLookServerbound
	PlayerLook

	VehicleMoveServerbound //0x10
	SteerBoat
	CraftRecipeRequest
	PlayerAbilitiesServerbound
	PlayerDigging
	EntityAction
	SteerVehicle
	CraftingBookData
	ResourcePackStatus
	AdvancementTab
	HeldItemChangeServerbound
	CreativeInventoryAction
	UpdateSign
	AnimationServerbound
	Spectate
	PlayerBlockPlacement
	UseItem
)
