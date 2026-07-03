<?php
class Table_JwtRefreshToken extends Omeka_Db_Table
{
    public function findByTokenHash(string $hash): ?JwtRefreshToken
    {
        $select = $this->getSelect()->where('token_hash = ?', $hash);
        return $this->fetchObject($select);
    }

    public function revokeByTokenHash(string $hash): void
    {
        $this->getDb()->update(
            $this->getTableName(),
            ['revoked' => 1],
            ['token_hash = ?' => $hash]
        );
    }

    public function isValid(string $hash): bool
    {
        $row = $this->findByTokenHash($hash);
        return $row
            && !$row->revoked
            && strtotime($row->expires_at) > time();
    }
}
