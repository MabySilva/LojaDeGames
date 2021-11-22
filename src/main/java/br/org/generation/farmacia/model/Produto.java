package br.org.generation.farmacia.model;

import java.math.BigDecimal;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Positive;
import javax.validation.constraints.Size;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@Entity
@Table(name = "tb_produto")
public class Produto {
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private long idProd;
	
	@NotBlank(message = "O nome é obrigatório")
	@Size(min = 2, max = 120, message = "O nome deve conter entre 2 a 120 caracteres")
	private String nomeProd;
	
	@NotBlank(message = "A descrição é obrigatória")
	@Size(max = 1000, message = "A descrição deve conter até 1000 caracteres")
	private String descricaoProd;
	
	@NotBlank(message = "O nome do laboratório é obrigatório")
	@Size(max = 60, message = "O nome deve conter até 60 caracteres")
	private String laboratorioProd;
	
	@NotBlank(message = "A classificacao é obrigatória")
	@Size(min = 5, max = 60, message = "A classificacao deve conter entre 5 a 60 caracteres")
	private String classificacaoProd;
	
	@NotNull(message = "O preço é obrigatório")
	@Positive(message = "O preço deve ser maior do que zero!")
	private BigDecimal precoProd;
	
	@ManyToOne
	@JsonIgnoreProperties("produto")
	private Categoria categoria;

	public long getIdProd() {
		return idProd;
	}

	public void setIdProd(long idProd) {
		this.idProd = idProd;
	}

	public String getNomeProd() {
		return nomeProd;
	}

	public void setNomeProd(String nomeProd) {
		this.nomeProd = nomeProd;
	}

	public String getDescricaoProd() {
		return descricaoProd;
	}

	public void setDescricaoProd(String descricaoProd) {
		this.descricaoProd = descricaoProd;
	}

	public String getLaboratorioProd() {
		return laboratorioProd;
	}

	public void setLaboratorioProd(String laboratorioProd) {
		this.laboratorioProd = laboratorioProd;
	}

	public String getClassificacaoProd() {
		return classificacaoProd;
	}

	public void setClassificacaoProd(String classificacaoProd) {
		this.classificacaoProd = classificacaoProd;
	}

	public BigDecimal getPrecoProd() {
		return precoProd;
	}

	public void setPrecoProd(BigDecimal precoProd) {
		this.precoProd = precoProd;
	}

	public Categoria getCategoria() {
		return categoria;
	}

	public void setCategoria(Categoria categoria) {
		this.categoria = categoria;
	}
	
}
