<?php
class JwtRefreshToken extends Omeka_Record_AbstractRecord
{
    public $token_hash;
    public $user_id;
    public $expires_at;
    public $revoked  = 0;
    public $created_at;

    protected function beforeSave($args)
    {
        if ($args['insert']) {
            $this->created_at = date('Y-m-d H:i:s');
        }
    }
}
