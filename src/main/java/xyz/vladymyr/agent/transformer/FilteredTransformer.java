package xyz.vladymyr.agent.transformer;

import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

/**
 * Just an extension of {@link Transformer} which
 * includes a two validation method in order to filter the classes and methods
 * for transformation.
 *
 * @author Vladymyr
 * @version 04/10/2019
 * @see xyz.vladymyr.agent.transformer.Transformer
 * @since 1.2
 */
public interface FilteredTransformer extends Transformer {

	/**
	 * Validates the class in order to know if it should continue
	 * to a further inspection of the methods. If it {@code true} but
	 * any of the methods passed {@link #validateMethod(MethodNode)} the client
	 * will be re-written without any changes (updated).
	 *
	 * @param cls       class
	 * @param classNode node of the class
	 * @return {@code true} if the class is valid
	 */
	boolean validateClass(Class<?> cls, ClassNode classNode);

	/**
	 * Method used to know which node is valid to apply the transformer on it
	 *
	 * @param methodNode node of the method
	 * @return {@code true} if the method is valid
	 */
	boolean validateMethod(MethodNode methodNode);
}
