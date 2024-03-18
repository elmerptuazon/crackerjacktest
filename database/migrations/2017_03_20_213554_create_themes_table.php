<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class CreateThemesTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up(): void
    {
        Schema::create('themes', function (Blueprint $table) {
            $table->bigIncrements('id')->index();
            $table->string('name')->index()->unique();
            $table->string('link')->unique();
            $table->string('notes')->nullable();
            $table->boolean('status')->default(1);
            $table->morphs('taggable');
            $table->timestamps();
            $table->softDeletes();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down(): void
    {
        Schema::dropIfExists('themes');
    }
}
